/*
 * Copyright 2019 Jack Henry & Associates, Inc.®
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.banno.vault

import cats.Show
import cats.data.Chain
import cats.effect.kernel.Clock
import cats.effect.{Async, Ref}
import cats.implicits.*
import cats.kernel.Eq
import com.banno.vault.MockVaultService.*
import com.banno.vault.MockVaultService.InternalLog.*
import com.banno.vault.MockVaultService.Role.{AppRole, K8s}
import com.banno.vault.models.VaultToken
import io.circe.syntax.*
import io.circe.{Decoder, DecodingFailure, Json}
import org.http4s.*
import org.http4s.Uri.Path
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.dsl.Http4sDsl
import org.typelevel.ci.CIString

import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit.SECONDS
import scala.concurrent.duration.{DurationInt, DurationLong, FiniteDuration}

class MockVaultService[F[_]: Async](
    activeTokensRef: Ref[F, Map[String, ActiveToken]],
    activeLeasesRef: Ref[F, Map[String, ActiveLease]],
    val rolesRef: Ref[F, Map[Role, LeaseTemplate]],
    val secretsRef: Ref[F, Map[Path, Secret]],
    logsRef: Ref[F, Chain[InternalLog]],
    inconsistencyLevelRef: Ref[F, Map[Path, Int]],
    tokenTracker: Ref[F, Map[Role, Int]],
    leaseTracker: Ref[F, Map[Role, Int]]
) {

  private def appendToLog(l: InternalLog): F[Unit] = logsRef.update(_.append(l))

  private def nextClientToken(role: Role): F[String] =
    tokenTracker.get.flatMap { map =>
      val tokenNumber = map.getOrElse(role, -1) + 1
      tokenTracker
        .set(map.updated(role, tokenNumber))
        .as(s"${role.logId} token $tokenNumber")
    }

  private def nextLeaseId(role: Role): F[String] =
    leaseTracker.get.flatMap { map =>
      val tokenNumber = map.getOrElse(role, -1) + 1
      leaseTracker
        .set(map.updated(role, tokenNumber))
        .as(s"${role.logId} lease $tokenNumber")
    }

  def activeTokens: F[Vector[ActiveToken]] =
    activeTokensRef.get.map(_.values.toVector)
  def activeLeases: F[Vector[ActiveLease]] =
    activeLeasesRef.get.map(_.values.toVector)

  def roles: F[Map[Role, LeaseTemplate]] = rolesRef.get
  def secrets: F[Map[Path, Secret]] = secretsRef.get

  def addRoles(
      role0: (Role, LeaseTemplate),
      roleN: (Role, LeaseTemplate)*
  ): F[Unit] =
    rolesRef.update(_ ++ (role0 :: roleN.toList))

  /** Set the number of calls that will return `412 Precondition Failed` to
    * simulate eventual consistency issues.
    * @param level
    *   Any value less than 0 will be normalized to 0
    */
  def setEventualInconsistencyLevel(path: Path, level: Int): F[Unit] =
    inconsistencyLevelRef.update(_.updated(path, level.max(0)))

  /** Insert a secret
    *
    * Note: a prefix of `v1/secret/` is assumed and should not be included
    */
  def addV1Secrets(secret0: (Path, Secret), secretN: (Path, Secret)*): F[Unit] =
    addV1Secrets(secret0 :: secretN.toList)

  def addV1Secrets(secrets: List[(Path, Secret)]): F[Unit] =
    secretsRef.update(_ ++ secrets)

  /** @see
    *   [[allLogs]]
    * @return
    *   The `MockVaultService` logs, which summarize what's been happening since
    *   the last call to `clearLogs`
    */
  def logs: F[Vector[Log]] =
    logsRef.get.map(_.toVector.map(_.external).filterNot(_.isResponseLog))

  /** This also includes response logs, which are usually a bit too noisy to
    * really be useful.
    * @see
    *   [[logs]]
    * @return
    *   The `MockVaultService` logs, which summarize what's been happening since
    *   the last call to `clearLogs`
    */
  def allLogs: F[Vector[Log]] =
    logsRef.get.map(_.toVector.map(_.external).filterNot(_.isResponseLog))

  /** Clear the `MockVaultService` logs
    */
  def clearLogs: F[Unit] = logsRef.set(Chain.empty)

  /** Formats a bunch of stuff about the roles, secrets, and more verbose logs.
    *
    * Mostly handy when tests fail
    */
  def clueForMUnit: F[String] =
    (
      roles.map(_.toVector),
      secrets.map(_.toVector),
      logsRef.get.map(_.toVector)
    ).mapN { (roles, secrets, logs) =>
      val text = List(
        roles
          .map { case (role, template) => s"${role.logId} -> $template" }
          .mkString("Roles\n=====\n", "\n", "\n"),
        secrets
          .map { case (path, Secret(roles, data, leaseOpt)) =>
            s"""${path.renderString}
               |Allowed: ${roles.map(_.logId).mkString(", ")}
               |Lease: $leaseOpt
               |Data: ${data.spaces2}
               |""".stripMargin
          }
          .mkString("Secrets\n=======\n", "\n", "\n"),
        logs.mkString("Server Logs\n===========\n", "\n", "\n")
      ).mkString("\n")
      text
    }

  val httpApp: HttpApp[F] = {
    object dsl extends Http4sDsl[F]
    import dsl.*

    def errorBody(messages: String*): Json =
      Json.obj("errors" := messages.toList)

    def makeApp(
        handle: (Instant, Path) => PartialFunction[Request[F], F[Response[F]]]
    ): HttpApp[F] =
      HttpApp.apply[F] { req =>
        for {
          now <- Clock[F].realTimeInstant
          path = req.uri.path
          _ <- activeTokensRef.flatModify { activeTokens =>
            val (fresh, stale) = activeTokens.partition {
              case (_, activeToken) =>
                now.isBefore(activeToken.expires) && now.isBefore(
                  activeToken.dies
                )
            }
            fresh -> stale.toVector.traverse_ { case (_, activeToken) =>
              appendToLog(InternalLog.TokenExpired(now, path, activeToken))
            }
          }
          _ <- activeLeasesRef.flatModify { activeLeases =>
            val (fresh, stale) = activeLeases.partition {
              case (_, activeLease) =>
                now.isBefore(activeLease.expires) && now.isBefore(
                  activeLease.dies
                )
            }
            fresh -> stale.toVector.traverse_ { case (_, activeLease) =>
              appendToLog(InternalLog.LeaseExpired(now, path, activeLease))
            }
          }
          inconsistencyLevel <- inconsistencyLevelRef.modify { map =>
            val oldLevel = map.getOrElse(path, 0).max(0)
            val newLevel = (oldLevel - 1).max(0)
            val updatedMap =
              if (newLevel <= 0) map - path
              else map.updated(path, newLevel)
            (updatedMap, oldLevel)
          }
          response <-
            if (inconsistencyLevel > 0)
              appendToLog(
                InternalLog.PresentlyInconsistent(now, path, inconsistencyLevel)
              ) >>
                PreconditionFailed(
                  errorBody(
                    s"Presently at Eventual Inconsistency level $inconsistencyLevel"
                  )
                )
            else
              handle(now, path)
                .lift(req)
                .map(_.onError { case throwable =>
                  appendToLog(InternalLog.ThrownException(now, path, throwable))
                })
                .getOrElse(
                  NotImplemented(errorBody("Endpoint not implemented"))
                )

          responseLog <- response.status match {
            case s @ Status.NoContent =>
              InternalLog.Success(now, path, s, none).pure[F]
            case s if s.isSuccess =>
              response.json.map(b => InternalLog.Success(now, path, s, b.some))
            case s => response.json.map(InternalLog.Failure(now, path, s, _))
          }
          _ <- appendToLog(responseLog)
        } yield response
      }

    makeApp { (now, path) =>
      def badRequest(messages: String*): F[Response[F]] =
        BadRequest(errorBody(messages *))

      def findVaultToken(
          req: Request[F]
      )(f: String => F[Response[F]]): F[Response[F]] =
        req.headers
          .get(CIString("X-Vault-Token"))
          .map(_.head.value)
          .fold(Forbidden(errorBody("Missing token header")))(f(_))

      def checkVaultToken(
          req: Request[F]
      )(resp: ActiveToken => F[Response[F]]): F[Response[F]] =
        activeTokensRef.get.flatMap { validTokens =>
          findVaultToken(req) { clientToken =>
            validTokens
              .get(clientToken) match {
              case Some(activeToken) => resp(activeToken)
              case None =>
                appendToLog(
                  InternalLog.TokenNotFound(now, path, clientToken)
                ) *>
                  Forbidden(errorBody("Invalid token"))
            }
          }
        }

      def handleLogin[A <: Role: Decoder](req: Request[F]): F[Response[F]] =
        for {
          role <- req.decodeJson[A]
          knownRoles <- rolesRef.get
          resp <- knownRoles
            .get(role)
            .fold(Forbidden(errorBody("Invalid role"))) { template =>
              for {
                id <- nextClientToken(role)
                vaultToken = VaultToken(
                  id,
                  template.duration.toSeconds,
                  template.renewable
                )
                activeToken = ActiveToken(
                  token = vaultToken,
                  expires = now.plusSeconds(vaultToken.leaseDuration),
                  dies = now.plusSeconds(template.maxDuration.toSeconds),
                  role = role
                )
                _ <- appendToLog(InternalLog.Login(now, path, activeToken))
                _ <- activeTokensRef.update(
                  _.updated(vaultToken.clientToken, activeToken)
                )
                resp <- Ok(Json.obj("auth" := vaultToken))
              } yield resp
            }
        } yield resp

      def createLease(
          role: Role,
          token: VaultToken,
          template: LeaseTemplate
      ): F[ActiveLease] =
        nextLeaseId(role)
          .map(
            ActiveLease(
              _,
              leaseDuration = template.duration.toSeconds,
              renewable = template.renewable,
              expires = now.plusSeconds(template.duration.toSeconds),
              dies = now.plusSeconds(template.maxDuration.toSeconds),
              role = role
            )
          )
          .flatTap { activeLease =>
            appendToLog(
              InternalLog.LeaseCreated(now, path, token, activeLease)
            ) *>
              activeLeasesRef.update(
                _.updated(activeLease.leaseId, activeLease)
              )
          }

      {
        case req @ POST -> Root / "v1" / "auth" / "token" / "renew-self" =>
          checkVaultToken(req) {
            case oldToken @ ActiveToken(token, _, dies, _) =>
              if (!token.renewable) badRequest("Not Renewable")
              else
                req.decodeJson[IncrementValue].flatMap {
                  case IncrementValue(iv) =>
                    val (newExpires, newToken) = {
                      val tentativeExpires = now.plusSeconds(iv.toSeconds)
                      if (tentativeExpires.isBefore(dies))
                        tentativeExpires -> token
                          .copy(leaseDuration = iv.toSeconds)
                      else
                        dies -> token.copy(
                          leaseDuration = now.until(dies, SECONDS),
                          renewable = false
                        )
                    }
                    val activeToken =
                      oldToken.copy(token = newToken, expires = newExpires)
                    for {
                      _ <- appendToLog(
                        InternalLog.TokenRenewed(now, path, activeToken)
                      )
                      _ <- activeTokensRef.update(
                        _.updated(token.clientToken, activeToken)
                      )
                      resp <- Ok {
                        Json.obj(
                          "auth" :=
                            newToken.asJson
                              .deepMerge(
                                Json.obj(
                                  "policies" := List("web", "stage"),
                                  "metadata" := Json.obj("user" := "armon")
                                )
                              )
                        )
                      }
                    } yield resp
                }
          }

        case req @ POST -> Root / "v1" / "auth" / "token" / "revoke-self" =>
          checkVaultToken(req) { activeToken =>
            appendToLog(InternalLog.TokenRevoked(now, path, activeToken)) *>
              activeTokensRef.update(_ - activeToken.token.clientToken) *>
              NoContent()
          }

        case req @ POST -> Root / "v1" / "auth" / "approle" / "login" =>
          handleLogin[AppRole](req)

        case req @ POST -> Root / "v1" / "auth" / "kubernetes" / "login" =>
          handleLogin[K8s](req)

        case req @ POST -> Root / "v1" / "auth" / "kubernetes2" / "login" =>
          handleLogin[K8s](req)

        case req @ GET -> "v1" /: "secret" /: secretPath =>
          checkVaultToken(req) { case ActiveToken(token, _, _, role) =>
            secretsRef.get.flatMap { secrets =>
              secrets.get(secretPath) match {
                case None =>
                  appendToLog(
                    InternalLog.SecretNotFound(now, path, token, secretPath)
                  ) *>
                    NotFound(errorBody("No secret at path"))
                case Some(secret) =>
                  if (!secret.roles.contains(role))
                    appendToLog(
                      InternalLog
                        .SecretForbidden(now, path, token, secretPath, secret)
                    ) *>
                      Forbidden(errorBody("Role not permitted"))
                  else
                    appendToLog(
                      InternalLog
                        .SecretViewed(now, path, token, secretPath, secret)
                    ) *>
                      secret.leaseOpt
                        .fold(none[ActiveLease].pure[F])(
                          createLease(role, token, _).map(_.some)
                        )
                        .flatMap { leaseOpt =>
                          Ok(
                            Json.obj(
                              "data" := secret.data,
                              "lease_duration" := leaseOpt.map(_.leaseDuration),
                              "lease_id" := leaseOpt.map(_.leaseId),
                              "renewable" := leaseOpt.map(_.renewable)
                            )
                          )
                        }
              }
            }
          }

        case req @ POST -> "v1" /: "secret" /: rawSecretPath =>
          val secretPath = rawSecretPath.toAbsolute
          checkVaultToken(req) { case ActiveToken(token, _, _, role) =>
            req.decodeJson[Json].flatMap { body =>
              val leaseOpt =
                body.hcursor.downField("ttl").as[Long].toOption.map { ttl =>
                  LeaseTemplate(ttl.seconds, renewable = true, ttl.seconds)
                }

              val secret = Secret(role.pure[List], body, leaseOpt)

              appendToLog(
                InternalLog.SecretCreated(now, path, token, secretPath, secret)
              ) *>
                secret.leaseOpt
                  .fold(none[ActiveLease].pure[F])(
                    createLease(role, token, _).map(_.some)
                  )
                  .flatMap { leaseOpt =>
                    Ok(
                      Json.obj(
                        "data" := secret.data,
                        "lease_duration" := leaseOpt.map(_.leaseDuration),
                        "lease_id" := leaseOpt.map(_.leaseId),
                        "renewable" := leaseOpt.map(_.renewable)
                      )
                    )
                  }
            }
          }

        case req @ DELETE -> "v1" /: "secret" /: rawSecretPath =>
          val secretPath = rawSecretPath.toAbsolute
          checkVaultToken(req) { case ActiveToken(token, _, _, role) =>
            secretsRef.get.flatMap { secrets =>
              secrets.get(secretPath) match {
                case None =>
                  appendToLog(
                    InternalLog.SecretNotFound(now, path, token, secretPath)
                  ) *>
                    NotFound(errorBody("No secret at path"))
                case Some(secret) =>
                  if (!secret.roles.contains(role))
                    appendToLog(
                      InternalLog
                        .SecretForbidden(now, path, token, secretPath, secret)
                    ) *>
                      Forbidden(errorBody("Role not permitted"))
                  else
                    appendToLog(
                      InternalLog.SecretDeleted(now, path, token, secretPath)
                    ) *>
                      secretsRef.update(_ - secretPath) *>
                      NoContent()
              }
            }
          }

        case req @ PUT -> Root / "v1" / "sys" / "leases" / "renew" =>
          checkVaultToken(req) { case ActiveToken(token, _, _, role) =>
            req.decodeJson[IncrementLease].flatMap {
              case IncrementLease(leaseId, increment) =>
                activeLeasesRef.get.flatMap { activeLeases =>
                  activeLeases.get(leaseId) match {
                    case None =>
                      appendToLog(
                        InternalLog.LeaseNotFound(now, path, token, leaseId)
                      ) *>
                        NotFound(errorBody("No lease matching lease_id"))
                    case Some(activeLease) =>
                      if (!activeLease.renewable) badRequest("Not Renewable")
                      else if (role =!= activeLease.role)
                        appendToLog(
                          InternalLog
                            .LeaseForbidden(now, path, token, activeLease)
                        ) *>
                          Forbidden(errorBody("Role not permitted"))
                      else {
                        val newExpires = now.plusSeconds(increment)
                        val newLease =
                          if (newExpires.isBefore(activeLease.dies))
                            activeLease.copy(
                              leaseDuration = increment,
                              expires = now.plusSeconds(increment)
                            )
                          else {
                            activeLease.copy(
                              leaseDuration =
                                now.until(activeLease.dies, SECONDS),
                              expires = activeLease.dies,
                              renewable = false
                            )
                          }
                        for {
                          _ <- appendToLog(
                            InternalLog.LeaseRenewed(now, path, token, newLease)
                          )
                          _ <- activeLeasesRef.update(
                            _.updated(activeLease.leaseId, newLease)
                          )
                          resp <- Ok(
                            Json.obj(
                              "lease_duration" := newLease.leaseDuration,
                              "lease_id" := newLease.leaseId,
                              "renewable" := newLease.renewable
                            )
                          )
                        } yield resp
                      }
                  }
                }
            }
          }

        case req @ PUT -> Root / "v1" / "sys" / "leases" / "revoke" =>
          checkVaultToken(req) { case ActiveToken(token, _, _, role) =>
            req.decodeJson[Lease].flatMap { case Lease(leaseId) =>
              activeLeasesRef.get.flatMap { activeLeases =>
                activeLeases.get(leaseId) match {
                  case None =>
                    appendToLog(
                      InternalLog.LeaseNotFound(now, path, token, leaseId)
                    ) *>
                      NotFound(errorBody("No lease matching lease_id"))
                  case Some(activeLease) =>
                    if (role =!= activeLease.role)
                      appendToLog(
                        InternalLog
                          .LeaseForbidden(now, path, token, activeLease)
                      ) *>
                        Forbidden(errorBody("Role not permitted"))
                    else
                      appendToLog(
                        InternalLog.LeaseRevoked(now, path, token, activeLease)
                      ) *>
                        activeLeasesRef.update(_ - activeLease.leaseId) *>
                        NoContent()
                }
              }
            }
          }
      }
    }
  }

  val client: Client[F] = Client.fromHttpApp(httpApp)
}

object MockVaultService {

  def init[F[_]: Async]: F[MockVaultService[F]] =
    (
      Ref[F].of(Map.empty[String, ActiveToken]),
      Ref[F].of(Map.empty[String, ActiveLease]),
      Ref[F].of(Map.empty[Role, LeaseTemplate]),
      Ref[F].of(Map.empty[Path, Secret]),
      Ref[F].empty[Chain[InternalLog]],
      Ref[F].of(Map.empty[Path, Int]),
      Ref[F].of(Map.empty[Role, Int]),
      Ref[F].of(Map.empty[Role, Int])
    ).mapN(new MockVaultService[F](_, _, _, _, _, _, _, _))

  sealed trait Role {
    def logId: String
  }
  object Role {
    final case class AppRole(role_id: String) extends Role {
      override def logId: String = s"app:$role_id"
    }

    object AppRole {
      implicit val roleIdDecoder: Decoder[AppRole] = Decoder.instance[AppRole] {
        c =>
          Decoder.resultInstance
            .map(c.downField("role_id").as[String])(AppRole(_))
      }
    }

    final case class K8s(role: String, jwt: String) extends Role {
      override def logId: String = s"k8s:$role"
    }

    object K8s {
      implicit val decoder: Decoder[K8s] =
        Decoder.forProduct2("role", "jwt")(K8s.apply)
    }

    implicit val eq: Eq[Role] = Eq.fromUniversalEquals
    implicit val show: Show[Role] = Show.show(_.logId)
  }

  final case class LeaseTemplate(
      duration: FiniteDuration,
      renewable: Boolean,
      maxDuration: FiniteDuration
  ) {
    override def toString: String =
      s"LeaseTemplate(duration: $duration, renewable: $renewable, maxDuration: $maxDuration)"
  }
  object LeaseTemplate {
    def renewable(duration: FiniteDuration): LeaseTemplate = LeaseTemplate(
      duration = duration,
      renewable = true,
      maxDuration = duration
    )

    def renewable(
        duration: FiniteDuration,
        maxDuration: FiniteDuration
    ): LeaseTemplate = LeaseTemplate(
      duration = duration,
      renewable = true,
      maxDuration = maxDuration
    )
  }

  final case class ActiveLease(
      leaseId: String,
      leaseDuration: Long,
      renewable: Boolean,
      expires: Instant,
      dies: Instant,
      role: Role
  )
  final case class ActiveToken(
      token: VaultToken,
      expires: Instant,
      dies: Instant,
      role: Role
  )
  final case class Secret(
      roles: List[Role],
      data: Json,
      leaseOpt: Option[LeaseTemplate]
  )

  final case class VaultValue(value: String)
  object VaultValue {
    implicit val vaultValueDecoder: Decoder[VaultValue] =
      Decoder.instance[VaultValue] { c =>
        Decoder.resultInstance
          .map(c.downField("value").as[String])(VaultValue(_))
      }
  }

  final case class TokenValue(token: String)
  object TokenValue {
    implicit val tokenValueDecoder: Decoder[TokenValue] =
      Decoder.instance[TokenValue] { c =>
        Decoder.resultInstance
          .map(c.downField("token").as[String])(TokenValue(_))
      }
  }

  final case class IncrementValue(increment: FiniteDuration)
  object IncrementValue {
    implicit val incrementValueDecoder: Decoder[IncrementValue] =
      Decoder
        .instance[IncrementValue] { c =>
          c.as[String]
            .flatMap { raw =>
              if (raw.endsWith("s")) raw.dropRight(1).asRight
              else if (!raw.lastOption.forall(_.isDigit))
                Left(
                  DecodingFailure(
                    "Only seconds are currently supported",
                    c.history
                  )
                )
              else raw.asRight
            }
            .flatMap { raw =>
              Either
                .catchNonFatal(raw.toInt)
                .leftMap(_ =>
                  DecodingFailure("Not an integer string", c.history)
                )
            }
            .map(_.seconds)
            .map(IncrementValue(_))
        }
        .at("increment")
  }

  final case class IncrementLease(lease_id: String, increment: Long)
  object IncrementLease {
    implicit val incrementLeaseDecoder: Decoder[IncrementLease] =
      Decoder.forProduct2("lease_id", "increment")(IncrementLease.apply)
  }

  final case class Lease(lease_id: String)
  object Lease {
    implicit val leaseDecoder: Decoder[Lease] =
      Decoder.forProduct1("lease_id")(Lease.apply)
  }

  sealed trait InternalLog {
    override def toString: String = {
      import InternalLog.ShowsForToString.*
      this match {
        case PresentlyInconsistent(at, path, level) =>
          show"$at ($path)\n  Presently inconsistent at level $level"
        case Success(at, path, status, Some(body)) =>
          show"$at ($path)\n  Success: $status\n  ${body.noSpaces}"
        case Success(at, path, status, None) =>
          show"$at ($path)\n  Success: $status"
        case Failure(at, path, status, body) =>
          show"$at ($path)\n  Failure: $status\n  ${body.noSpaces}"
        case ThrownException(at, path, throwable) =>
          show"$at ($path)\n  ${throwable.toString}"
        case TokenNotFound(at, path, clientToken) =>
          show"$at ($path)\n  Token not found: $clientToken"
        case TokenExpired(at, path, token) =>
          show"$at ($path)\n  Token expired\n  $token"
        case TokenRenewed(at, path, token) =>
          show"$at ($path)\n  Token renewed\n  $token"
        case TokenRevoked(at, path, token) =>
          show"$at ($path)\n  Token revoked\n  $token"
        case Login(at, path, token) =>
          show"$at ($path)\n  Token created\n  $token"
        case SecretNotFound(at, path, token, secretPath) =>
          show"$at ($path)\n  Secret not found by ${token.clientToken}: $secretPath"
        case SecretForbidden(at, path, token, secretPath, secret) =>
          show"$at ($path)\n  Role rejected for $secretPath: ${token.clientToken}\n  Allowed roles: ${secret.roles.mkString_(",")}"
        case SecretViewed(at, path, token, secretPath, secret) =>
          show"$at ($path)\n  Secret at $secretPath viewed by ${token.clientToken}\n  ${secret.data.noSpaces}"
        case SecretCreated(at, path, token, secretPath, secret) =>
          show"$at ($path)\n  Secret created at $secretPath by ${token.clientToken}\n  ${secret.data.noSpaces}"
        case SecretDeleted(at, path, token, secretPath) =>
          show"$at ($path)\n  Secret at $secretPath deleted by ${token.clientToken}"
        case LeaseCreated(at, path, token, lease) =>
          show"$at ($path) by ${token.clientToken}\n  Lease created\n  $lease"
        case LeaseExpired(at, path, lease) =>
          show"$at ($path)\n  Lease expired\n  $lease"
        case LeaseRenewed(at, path, token, lease) =>
          show"$at ($path) by ${token.clientToken}\n  Lease renewed\n  $lease"
        case LeaseRevoked(at, path, token, lease) =>
          show"$at ($path) by ${token.clientToken}\n  Lease revoked\n  $lease"
        case LeaseForbidden(at, path, token, lease) =>
          show"$at ($path)\n  Role rejected for lease ${lease.leaseId}: ${token.clientToken}\n  Allowed roles: ${lease.role}"
        case LeaseNotFound(at, path, token, leaseId) =>
          show"$at ($path)\n  Lease not found by ${token.clientToken}: $leaseId"
      }
    }

    def external: Log = this match {
      case PresentlyInconsistent(_, path, level) =>
        Log.PresentlyInconsistent(path, level)
      case Success(_, path, status, _) => Log.Success(path, status)
      case Failure(_, path, status, _) => Log.Failure(path, status)
      case ThrownException(_, path, throwable) =>
        Log.ThrownException(path, throwable)
      case TokenNotFound(_, path, _) => Log.TokenNotFound(path)
      case TokenExpired(_, path, token) =>
        Log.TokenExpired(path, token.token.clientToken)
      case TokenRenewed(_, path, token) =>
        Log.TokenRenewed(path, token.token.clientToken)
      case TokenRevoked(_, path, token) =>
        Log.TokenRevoked(path, token.token.clientToken)
      case Login(_, path, token) =>
        Log.Login(path, token.role, token.token.clientToken)
      case SecretNotFound(_, path, token, secretPath) =>
        Log.SecretNotFound(path, token.clientToken, secretPath)
      case SecretForbidden(_, path, token, secretPath, secret) =>
        Log.SecretForbidden(path, token.clientToken, secretPath, secret.roles)
      case SecretViewed(_, path, token, secretPath, _) =>
        Log.SecretViewed(path, token.clientToken, secretPath)
      case SecretCreated(_, path, token, secretPath, secret) =>
        Log.SecretCreated(path, token.clientToken, secretPath, secret.data)
      case SecretDeleted(_, path, token, secretPath) =>
        Log.SecretDeleted(path, token.clientToken, secretPath)
      case LeaseCreated(_, path, token, lease) =>
        Log.LeaseCreated(path, token.clientToken, lease.leaseId)
      case LeaseExpired(_, path, lease) => Log.LeaseExpired(path, lease.leaseId)
      case LeaseRenewed(_, path, token, lease) =>
        Log.LeaseRenewed(path, token.clientToken, lease.leaseId)
      case LeaseRevoked(_, path, token, lease) =>
        Log.LeaseRevoked(path, token.clientToken, lease.leaseId)
      case LeaseForbidden(_, path, token, lease) =>
        Log.LeaseForbidden(path, token.clientToken, lease.leaseId)
      case LeaseNotFound(_, path, token, leaseId) =>
        Log.LeaseNotFound(path, token.clientToken, leaseId)
    }
  }
  object InternalLog {
    final case class PresentlyInconsistent(
        at: Instant,
        path: Path,
        inconsistencyLevel: Int
    ) extends InternalLog
    final case class Success(
        at: Instant,
        path: Path,
        status: Status,
        body: Option[Json]
    ) extends InternalLog
    final case class Failure(
        at: Instant,
        path: Path,
        status: Status,
        body: Json
    ) extends InternalLog
    final case class ThrownException(
        at: Instant,
        path: Path,
        throwable: Throwable
    ) extends InternalLog

    final case class TokenNotFound(at: Instant, path: Path, clientToken: String)
        extends InternalLog
    final case class TokenExpired(at: Instant, path: Path, token: ActiveToken)
        extends InternalLog
    final case class TokenRenewed(at: Instant, path: Path, token: ActiveToken)
        extends InternalLog
    final case class TokenRevoked(at: Instant, path: Path, token: ActiveToken)
        extends InternalLog

    final case class Login(at: Instant, path: Path, token: ActiveToken)
        extends InternalLog

    final case class SecretNotFound(
        at: Instant,
        path: Path,
        token: VaultToken,
        secretPath: Path
    ) extends InternalLog
    final case class SecretForbidden(
        at: Instant,
        path: Path,
        token: VaultToken,
        secretPath: Path,
        secret: Secret
    ) extends InternalLog
    final case class SecretViewed(
        at: Instant,
        path: Path,
        token: VaultToken,
        secretPath: Path,
        secret: Secret
    ) extends InternalLog
    final case class SecretCreated(
        at: Instant,
        path: Path,
        token: VaultToken,
        secretPath: Path,
        secret: Secret
    ) extends InternalLog
    final case class SecretDeleted(
        at: Instant,
        path: Path,
        token: VaultToken,
        secretPath: Path
    ) extends InternalLog

    final case class LeaseCreated(
        at: Instant,
        path: Path,
        token: VaultToken,
        lease: ActiveLease
    ) extends InternalLog
    final case class LeaseExpired(at: Instant, path: Path, lease: ActiveLease)
        extends InternalLog
    final case class LeaseRenewed(
        at: Instant,
        path: Path,
        token: VaultToken,
        lease: ActiveLease
    ) extends InternalLog
    final case class LeaseRevoked(
        at: Instant,
        path: Path,
        token: VaultToken,
        lease: ActiveLease
    ) extends InternalLog
    final case class LeaseForbidden(
        at: Instant,
        path: Path,
        token: VaultToken,
        lease: ActiveLease
    ) extends InternalLog
    final case class LeaseNotFound(
        at: Instant,
        path: Path,
        token: VaultToken,
        leaseId: String
    ) extends InternalLog
    private object ShowsForToString {
      implicit val showPath: Show[Path] = Show.show(_.renderString)
      implicit val showJson: Show[Json] = Show.show(_.noSpaces)
      implicit val showInstant: Show[Instant] =
        Show.show(DateTimeFormatter.ISO_INSTANT.format(_))
      implicit val showStatus: Show[Status] = Show.show { status =>
        if (status.reason.nonEmpty) s"${status.code} ${status.reason}"
        else status.code.toString
      }
      implicit val showActiveToken: Show[ActiveToken] = Show.show {
        case ActiveToken(
              VaultToken(clientToken, _, renewable),
              expires,
              dies,
              role
            ) =>
          show"ActiveToken($clientToken, expires: $expires (dies at $dies), renewable: $renewable, owner: $role)"
      }
      implicit val showActiveLease: Show[ActiveLease] = Show.show {
        case ActiveLease(leaseId, _, renewable, expires, dies, role) =>
          show"ActiveLease($leaseId, expires: $expires (dies at $dies), renewable: $renewable, owner: $role)"
      }
    }
  }

  sealed trait Log {
    def isResponseLog: Boolean = this match {
      case _: Log.Success | _: Log.Failure => true
      case _                               => false
    }
  }
  object Log {
    final case class PresentlyInconsistent(path: Path, count: Int) extends Log
    final case class Success(path: Path, status: Status) extends Log
    final case class Failure(path: Path, status: Status) extends Log
    final case class ThrownException(path: Path, throwable: Throwable)
        extends Log

    final case class TokenNotFound(path: Path) extends Log
    final case class TokenExpired(path: Path, token: String) extends Log
    final case class TokenRenewed(path: Path, token: String) extends Log
    final case class TokenRevoked(path: Path, token: String) extends Log

    final case class Login(path: Path, role: Role, token: String) extends Log

    final case class SecretNotFound(path: Path, token: String, secretPath: Path)
        extends Log
    final case class SecretForbidden(
        path: Path,
        token: String,
        secretPath: Path,
        allowedRoles: List[Role]
    ) extends Log
    final case class SecretViewed(path: Path, token: String, secretPath: Path)
        extends Log
    final case class SecretCreated(
        path: Path,
        token: String,
        secretPath: Path,
        data: Json
    ) extends Log
    final case class SecretDeleted(path: Path, token: String, secretPath: Path)
        extends Log

    final case class LeaseCreated(path: Path, token: String, leaseId: String)
        extends Log
    final case class LeaseExpired(path: Path, leaseId: String) extends Log
    final case class LeaseRenewed(path: Path, token: String, leaseId: String)
        extends Log
    final case class LeaseRevoked(path: Path, token: String, leaseId: String)
        extends Log
    final case class LeaseForbidden(path: Path, token: String, leaseId: String)
        extends Log
    final case class LeaseNotFound(path: Path, token: String, leaseId: String)
        extends Log
  }
}
