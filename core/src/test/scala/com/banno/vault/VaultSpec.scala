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

import java.util.UUID
import java.util.concurrent.TimeUnit
import cats.effect.{Concurrent, IO}
import cats.implicits.*
import com.banno.vault.models.{
  CertificateData,
  CertificateRequest,
  VaultApiError,
  VaultKeys,
  VaultRequestError,
  VaultSecret,
  VaultSecretRenewal,
  VaultToken
}
import io.circe.{Codec, Decoder, Json}
import io.circe.syntax.*
import org.http4s.*
import org.http4s.implicits.*
import org.http4s.dsl.Http4sDsl
import org.http4s.dsl.impl.QueryParamDecoderMatcher
import org.http4s.circe.*
import org.http4s.client.Client

import scala.concurrent.duration.*
import munit.{CatsEffectSuite, ScalaCheckEffectSuite}
import org.scalacheck.*

import scala.util.Random
import org.scalacheck.effect.PropF
import org.typelevel.ci.CIString

import scala.annotation.nowarn

class VaultSpec
    extends CatsEffectSuite
    with ScalaCheckEffectSuite
    with MissingPieces {

  case class RoleId(role_id: String, secret_id: Option[String])
  object RoleId {
    implicit val roleIdDecoder: Decoder[RoleId] = Decoder.instance[RoleId] {
      c =>
        (
          c.downField("role_id").as[String],
          c.downField("secret_id").as[Option[String]]
        ).mapN(RoleId.apply)
    }
  }

  case class RoleAndJwt(role: String, jwt: String)
  object RoleAndJwt {
    implicit val decoder: Decoder[RoleAndJwt] =
      Decoder.forProduct2("role", "jwt")(RoleAndJwt.apply)
  }

  case class GitHubToken(token: String)
  object GitHubToken {
    implicit val decoder: Decoder[GitHubToken] =
      Decoder[String].at("token").map(GitHubToken(_))
  }

  case class Password(password: String)
  object Password {
    implicit val decoder: Decoder[Password] =
      Decoder[String].at("password").map(Password(_))
  }

  case class VaultValue(value: String)
  object VaultValue {
    implicit val vaultValueDecoder: Decoder[VaultValue] =
      Decoder.instance[VaultValue] { c =>
        Decoder.resultInstance
          .map(c.downField("value").as[String])(VaultValue(_))
      }
  }

  case class TokenValue(token: String)
  object TokenValue {
    implicit val tokenValueDecoder: Decoder[TokenValue] =
      Decoder.instance[TokenValue] { c =>
        Decoder.resultInstance
          .map(c.downField("token").as[String])(TokenValue(_))
      }
  }
  case class IncrementValue(increment: String)
  object IncrementValue {
    implicit val incrementValueDecoder: Decoder[IncrementValue] =
      Decoder.instance[IncrementValue] { c =>
        Decoder.resultInstance
          .map(c.downField("increment").as[String])(IncrementValue(_))
      }
  }

  case class IncrementLease(lease_id: String, increment: Int)
  object IncrementLease {
    implicit val incrementLeaseDecoder: Decoder[IncrementLease] =
      Decoder.forProduct2("lease_id", "increment")(IncrementLease.apply)
  }

  case class Lease(lease_id: String)
  object Lease {
    implicit val leaseDecoder: Decoder[Lease] =
      Decoder.forProduct1("lease_id")(Lease.apply)
  }

  case class SelfManaged(key: String, kid: String)
  object SelfManaged {
    implicit val codec: Codec[SelfManaged] =
      Codec.forProduct2("key", "kid")(SelfManaged.apply)(sm => (sm.key, sm.kid))
  }

  implicit val certificateRequestDecoder: Decoder[CertificateRequest] =
    Decoder.forProduct7(
      "common_name",
      "alt_names",
      "ip_sans",
      "ttl",
      "format",
      "private_key_format",
      "exclude_cn_from_sans"
    )(CertificateRequest.apply)

  object ListQueryParamMatcher extends QueryParamDecoderMatcher[String]("list")

  val certificate: String = UUID.randomUUID().toString
  val issuing_ca: String = UUID.randomUUID().toString
  val ca_chain: String = UUID.randomUUID().toString
  val private_key: String = UUID.randomUUID().toString
  val private_key_type: String = UUID.randomUUID().toString
  val serial_number: String = UUID.randomUUID().toString

  val validRoleId: String = UUID.randomUUID().toString
  val validSecretId: String = UUID.randomUUID().toString
  val invalidJSONRoleId: String = UUID.randomUUID().toString
  val roleIdWithoutToken: String = UUID.randomUUID().toString
  val roleIdWithoutLease: String = UUID.randomUUID().toString

  val validKubernetesRole: String = UUID.randomUUID().toString
  val validKubernetesJwt: String =
    Random.alphanumeric
      .take(20)
      .mkString // simulate a signed jwt https://www.vaultproject.io/api/auth/kubernetes/index.html#login

  val validGitHubToken: String = UUID.randomUUID().toString

  val validUsername: String = UUID.randomUUID().toString
  val validPassword: String = UUID.randomUUID().toString

  val clientToken: String = UUID.randomUUID().toString
  val leaseDuration: Long = Random.nextLong()
  val leaseId: String = UUID.randomUUID().toString
  val renewable: Boolean = Random.nextBoolean()
  val increment: FiniteDuration =
    FiniteDuration(Random.nextInt().abs.toLong, TimeUnit.SECONDS)

  val postgresPass: String = UUID.randomUUID().toString
  val privateKey: String = UUID.randomUUID().toString

  val secretPostgresPassPath: String = "secret/postgres1/password"
  val secretPrivateKeyPath: String = "secret/data-services/private-key"
  val generateCertsPath: String = "pki/issue/ip"

  val validToken: VaultToken = VaultToken(clientToken, leaseDuration, renewable)
  val altValidToken: VaultToken =
    VaultToken(UUID.randomUUID().toString, leaseDuration, renewable)

  def mockVaultService[F[_]: Concurrent]: HttpRoutes[F] = {
    object dsl extends Http4sDsl[F]
    import dsl._

    def findVaultToken(req: Request[F]): Option[String] =
      req.headers.get(CIString("X-Vault-Token")).map(_.head.value)

    def checkVaultToken(req: Request[F])(resp: F[Response[F]]): F[Response[F]] =
      if (findVaultToken(req).contains(clientToken)) resp
      else BadRequest(Json.obj("errors" := List("Invalid Token")))

    def standardLoginResponses(identifier: String)(
        valid: (String, VaultToken),
        invalidJson: String,
        missingToken: String,
        missingLease: String
    ): F[Response[F]] = identifier match {
      case valid._1       => Ok(Json.obj("auth" := valid._2).noSpaces)
      case `invalidJson`  => Ok(s""" NOT A JSON """)
      case `missingToken` =>
        Ok(s"""
              |{
              | "auth": {
              |   "lease_duration": $leaseDuration
              | }
              |}""".stripMargin)
      case `missingLease` =>
        Ok(s"""
              |{
              | "auth": {
              |   "client_token": "$clientToken"
              | }
              |}""".stripMargin)
      case _ =>
        BadRequest(Json.obj("errors" := List("Invalid Token")))
    }

    HttpRoutes.of[F] {
      case req @ POST -> Root / "v1" / "auth" / "token" / "renew-self" =>
        checkVaultToken(req) {
          req.decodeJson[IncrementValue].flatMap { case IncrementValue(_) =>
            Ok(
              s"""
                 |{
                 |  "auth": {
                 |    "client_token": "${findVaultToken(req).getOrElse("")}",
                 |    "policies": [
                 |      "web",
                 |      "stage"
                 |    ],
                 |    "metadata": {
                 |      "user": "armon"
                 |    },
                 |    "lease_duration": 3600,
                 |    "renewable": $renewable
                 |  }
                 |}
               """.stripMargin
            )
          }
        }

      case req @ POST -> Root / "v1" / "auth" / "token" / "revoke-self" =>
        checkVaultToken(req)(NoContent())

      case req @ POST -> Root / "v1" / "auth" / "approle" / "login" =>
        req.decodeJson[RoleId].flatMap {
          case RoleId(role_id, None) =>
            standardLoginResponses(role_id)(
              valid = validRoleId -> validToken,
              invalidJson = invalidJSONRoleId,
              missingToken = roleIdWithoutToken,
              missingLease = roleIdWithoutLease
            )
          case RoleId(role_id, Some(`validSecretId`)) =>
            standardLoginResponses(role_id)(
              valid = validRoleId -> altValidToken,
              invalidJson = invalidJSONRoleId,
              missingToken = roleIdWithoutToken,
              missingLease = roleIdWithoutLease
            )
          case _ => BadRequest(Json.obj("errors" := List("Invalid secret_id")))
        }
      case req @ POST -> Root / "v1" / "auth" / "kubernetes" / "login" =>
        req.decodeJson[RoleAndJwt].flatMap {
          case RoleAndJwt(k8sRole, `validKubernetesJwt`) =>
            standardLoginResponses(k8sRole)(
              valid = validKubernetesRole -> validToken,
              invalidJson = invalidJSONRoleId,
              missingToken = roleIdWithoutToken,
              missingLease = roleIdWithoutLease
            )
          case _ => BadRequest(Json.obj("errors" := List("Invalid JWT")))
        }
      case req @ POST -> Root / "v1" / "auth" / "kubernetes2" / "login" =>
        req.decodeJson[RoleAndJwt].flatMap {
          case RoleAndJwt(`validKubernetesRole`, `validKubernetesJwt`) =>
            Ok(Json.obj("auth" := altValidToken).noSpaces)
          case _ => BadRequest(Json.obj("errors" := List("Invalid JWT")))
        }

      case req @ POST -> Root / "v1" / "auth" / "github" / "login" =>
        req.decodeJson[GitHubToken].flatMap { gitHubToken =>
          standardLoginResponses(gitHubToken.token)(
            valid = validGitHubToken -> validToken,
            invalidJson = invalidJSONRoleId,
            missingToken = roleIdWithoutToken,
            missingLease = roleIdWithoutLease
          )
        }

      case req @ POST -> Root / "v1" / "auth" / "userpass" / "login" / username =>
        req.decodeJson[Password].flatMap {
          case Password(`validPassword`) =>
            standardLoginResponses(username)(
              valid = validUsername -> validToken,
              invalidJson = invalidJSONRoleId,
              missingToken = roleIdWithoutToken,
              missingLease = roleIdWithoutLease
            )
          case _ => BadRequest(Json.obj("errors" := List("Invalid Password")))
        }

      case req @ GET -> Root / "v1" / "secret" / "postgres1" / "password" =>
        checkVaultToken(req) {
          Ok(s"""
                |{
                | "data": {
                |   "value": "$postgresPass"
                | },
                | "lease_duration": $leaseDuration,
                | "lease_id": "$leaseId",
                | "renewable": $renewable
                |}""".stripMargin)
        }
      case req @ GET -> Root / "v1" / "secret" / "data-services" / "private-key" =>
        checkVaultToken(req) {
          Ok(s"""
                |{
                | "data": {
                |   "value": "$privateKey"
                | },
                | "lease_duration": $leaseDuration,
                | "lease_id": "$leaseId",
                | "renewable": $renewable
                |}""".stripMargin)
        }

      case req @ POST -> Root / "v1" / "secret" / "selfmanaged" / "200" / kid =>
        checkVaultToken(req) {
          Ok(s"""
               |{
               | "data": {
               |   "key": "$privateKey",
               |   "kid": "$kid"
               | },
               | "lease_duration": $leaseDuration,
               | "lease_id": "$leaseId",
               | "renewable": $renewable
               |}""".stripMargin)
        }

      case req @ GET -> Root / "v1" / "secret" / "selfmanaged" / "204" / kid =>
        checkVaultToken(req) {
          Ok(s"""
               |{
               | "data": {
               |   "key": "$privateKey",
               |   "kid": "$kid"
               | },
               | "lease_duration": $leaseDuration,
               | "lease_id": "$leaseId",
               | "renewable": $renewable
               |}""".stripMargin)
        }

      case req @ POST -> Root / "v1" / "secret" / "selfmanaged" / "204" / _ =>
        checkVaultToken(req)(NoContent())

      case req @ POST -> Root / "v1" / "secret" / "selfmanaged" / "4xx" / _ =>
        checkVaultToken(req)(Forbidden())

      case req @ PUT -> Root / "v1" / "sys" / "leases" / "renew" =>
        checkVaultToken(req) {
          req.decodeJson[IncrementLease].flatMap { _ =>
            Ok(s"""
                  |{
                  | "lease_duration": $leaseDuration,
                  | "lease_id": "$leaseId",
                  | "renewable": $renewable
                  |}""".stripMargin)
          }
        }

      case req @ PUT -> Root / "v1" / "sys" / "leases" / "revoke" =>
        checkVaultToken(req) { req.decodeJson[Lease] >> NoContent() }

      case req @ POST -> Root / "v1" / "pki" / "issue" / "ip" =>
        checkVaultToken(req) {
          req.decodeJson[CertificateRequest].flatMap { _ =>
            Ok(s"""
                  |{
                  | "data": {
                  |   "certificate": "$certificate",
                  |   "issuing_ca": "$issuing_ca",
                  |   "ca_chain": ["$ca_chain"],
                  |   "private_key": "$private_key",
                  |   "private_key_type": "$private_key_type",
                  |   "serial_number": "$serial_number"
                  | },
                  | "lease_duration": $leaseDuration,
                  | "lease_id": "$leaseId",
                  | "renewable": $renewable
                  |}""".stripMargin)
          }
        }
      case req @ GET -> Root / "v1" / "secret" / "postgres" / "" :? ListQueryParamMatcher(
            _
          ) =>
        checkVaultToken(req) {
          Ok(s"""
                |{
                | "data": {
                |   "keys": ["postgres1", "postgres-pupper"]
                | }
                |}""".stripMargin)
        }

      case GET -> path =>
        BadRequest(
          Json.obj(
            "errors" := List(s"Path not mapped: $path")
          )
        )
    }
  }

  val mockClient: Client[IO] =
    Client.fromHttpApp(mockVaultService[IO].orNotFound)

  test("login works as expected when sending a valid roleId") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault.login(mockClient, uri)(validRoleId).assertEquals(validToken)
    }
  }

  test("login should fail when sending an invalid roleId") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .login(mockClient, uri)(UUID.randomUUID().toString)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("login should fail when the response is not valid JSON") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .login(mockClient, uri)(invalidJSONRoleId)
        .attempt
        .flatMap {
          case Left(
                e @ VaultRequestError(
                  message,
                  Some(_: MalformedMessageBodyFailure)
                )
              ) =>
            IO(assert(message.contains("Invalid JSON"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("login should fail when the response doesn't contains a token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .login(mockClient, uri)(roleIdWithoutToken)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("client_token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "login should fail when the response doesn't contains a lease duration"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .login(mockClient, uri)(roleIdWithoutLease)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("lease_duration"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginAppRoleAndSecretId works as expected when sending a valid roleId and secretId"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(validRoleId, validSecretId)
        .assertEquals(altValidToken)
    }
  }

  test("loginAppRoleAndSecretId should fail when sending an invalid roleId") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(
          UUID.randomUUID().toString,
          validSecretId
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginAppRoleAndSecretId should fail when sending an invalid secretId") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(
          validRoleId,
          UUID.randomUUID().toString
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid secret_id"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
        .assert
    }
  }

  test(
    "loginAppRoleAndSecretId should fail when the response is not valid JSON"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(
          invalidJSONRoleId,
          validSecretId
        )
        .attempt
        .flatMap {
          case Left(
                e @ VaultRequestError(
                  message,
                  Some(_: MalformedMessageBodyFailure)
                )
              ) =>
            IO(assert(message.contains("Invalid JSON"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginAppRoleAndSecretId should fail when the response doesn't contains a token"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(
          roleIdWithoutToken,
          validSecretId
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("client_token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginAppRoleAndSecretId should fail when the response doesn't contains a lease duration"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginAppRoleAndSecretId(mockClient, uri)(
          roleIdWithoutLease,
          validSecretId
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("lease_duration"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginKubernetes works as expected when sending valid role and jwt") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(
          validKubernetesRole,
          validKubernetesJwt
        )
        .assertEquals(validToken)
    }
  }

  test("loginKubernetes respects alternate mount points") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(
          validKubernetesRole,
          validKubernetesJwt,
          path"/auth/kubernetes2"
        )
        .assertEquals(altValidToken)
    }
  }

  test("loginKubernetes should fail when sending an invalid roleId") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(
          UUID.randomUUID().toString,
          validKubernetesJwt
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginKubernetes should fail when the response is not a valid JSON") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(invalidJSONRoleId, validKubernetesJwt)
        .attempt
        .flatMap {
          case Left(
                e @ VaultRequestError(
                  message,
                  Some(_: MalformedMessageBodyFailure)
                )
              ) =>
            IO(assert(message.contains("Invalid JSON"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginKubernetes should fail when the response doesn't contains a token"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(
          roleIdWithoutToken,
          validKubernetesJwt
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("client_token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginKubernetes should fail when the response doesn't contains a lease duration"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginKubernetes(mockClient, uri)(
          roleIdWithoutLease,
          validKubernetesJwt
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("lease_duration"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginGitHub works as expected when sending a valid GitHub token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginGitHub(mockClient, uri)(validGitHubToken)
        .assertEquals(validToken)
    }
  }

  test("loginGitHub should fail when sending an invalid GitHub token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginGitHub(mockClient, uri)(UUID.randomUUID().toString)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginGitHub should fail when the response is not valid JSON") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginGitHub(mockClient, uri)(invalidJSONRoleId)
        .attempt
        .flatMap {
          case Left(
                e @ VaultRequestError(
                  message,
                  Some(_: MalformedMessageBodyFailure)
                )
              ) =>
            IO(assert(message.contains("Invalid JSON"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginGitHub should fail when the response doesn't contains a token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginGitHub(mockClient, uri)(roleIdWithoutToken)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("client_token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginGitHub should fail when the response doesn't contains a lease duration"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginGitHub(mockClient, uri)(roleIdWithoutLease)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("lease_duration"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginUserPass works as expected when sending a valid username and password"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(validUsername, validPassword)
        .assertEquals(validToken)
    }
  }

  test("loginUserPass should fail when sending an invalid username") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(
          UUID.randomUUID().toString,
          validPassword
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginUserPass should fail when sending an invalid password") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(
          validUsername,
          UUID.randomUUID().toString
        )
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: VaultApiError))) =>
            IO(assert(message.contains("Invalid Password"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginUserPass should fail when the response is not valid JSON") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(invalidJSONRoleId, validPassword)
        .attempt
        .flatMap {
          case Left(
                e @ VaultRequestError(
                  message,
                  Some(_: MalformedMessageBodyFailure)
                )
              ) =>
            IO(assert(message.contains("Invalid JSON"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test("loginUserPass should fail when the response doesn't contains a token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(roleIdWithoutToken, validPassword)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("client_token"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "loginUserPass should fail when the response doesn't contains a lease duration"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .loginUserPass(mockClient, uri)(roleIdWithoutLease, validPassword)
        .attempt
        .flatMap {
          case Left(e @ VaultRequestError(message, Some(_: DecodeFailure))) =>
            IO(assert(message.contains("Missing required field"), clue(e))) *>
              IO(assert(message.contains("lease_duration"), clue(e)))
          case other =>
            IO[Unit](fail("Expected VaultRequestError", clues(other)))
        }
    }
  }

  test(
    "readSecret works as expected when requesting the postgres password with a valid"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .readSecret[IO, VaultValue](mockClient, uri)(
          clientToken,
          secretPostgresPassPath
        )
        .assertEquals(
          VaultSecret(
            VaultValue(postgresPass),
            leaseDuration.some,
            leaseId.some,
            renewable.some
          )
        )
    }
  }

  test(
    "readSecret works as expected when requesting the private key with a valid token"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .readSecret[IO, VaultValue](mockClient, uri)(
          clientToken,
          secretPrivateKeyPath
        )
        .assertEquals(
          VaultSecret(
            VaultValue(privateKey),
            leaseDuration.some,
            leaseId.some,
            renewable.some
          )
        )
    }
  }

  test(
    "readSecret works as expected when requesting the postgres password with an invalid token"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .readSecret[IO, VaultValue](mockClient, uri)(
          UUID.randomUUID().toString,
          secretPostgresPassPath
        )
        .attempt
        .map(_.isLeft)
        .assert
    }
  }

  test(
    "readSecret works as expected when requesting the private key with an invalid token"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .readSecret[IO, VaultValue](mockClient, uri)(
          UUID.randomUUID().toString,
          secretPrivateKeyPath
        )
        .attempt
        .map(_.isLeft)
        .assert
    }
  }

  test("readSecret suppresses echoing the data when JSON decoding fails") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .readSecret[IO, TokenValue](mockClient, uri)(
          clientToken,
          secretPrivateKeyPath
        )
        .redeem(
          error =>
            if (error.getMessage.contains(privateKey))
              PropF.falsified[IO].label("Secret data in the error message")
            else PropF.passed[IO].label("Secret data redacted"),
          _ => PropF.falsified[IO].label("Data should not be parseable")
        )
    }
  }

  test("listSecrets works as expected when requesting keys under path") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .listSecrets[IO](mockClient, uri)(clientToken, "/secret/postgres/")
        .assertEquals(VaultKeys(List("postgres1", "postgres-pupper")))
    }
  }

  test("renewToken works as expected when sending a valid token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .renewSelfToken[IO](mockClient, uri)(
          VaultToken(clientToken, 3600, renewable = true),
          1.hour
        )
        .assertEquals(VaultToken(clientToken, 3600, renewable))
    }
  }

  test("revokeToken works as expected when revoking a valid token") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .revokeSelfToken[IO](mockClient, uri)(
          VaultToken(clientToken, 3600, renewable = true)
        )
        .assertEquals(())
    }
  }

  test("renewLease works as expected when sending valid input arguments") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault
        .renewLease(mockClient, uri)(leaseId, increment, clientToken)
        .assertEquals(VaultSecretRenewal(leaseDuration, leaseId, renewable))
    }
  }

  test("revokeLease works as expected when sending valid input arguments") {
    PropF.forAllF(VaultArbitraries.validVaultUri) { uri =>
      Vault.revokeLease(mockClient, uri)(clientToken, leaseId).assertEquals(())
    }
  }

  test("generateCertificate works as expected when sending a valid token") {
    PropF.forAllF(
      VaultArbitraries.validVaultUri,
      VaultArbitraries.certRequestGen
    ) { (uri, certRequest) =>
      Vault
        .generateCertificate(mockClient, uri)(
          clientToken,
          generateCertsPath,
          certRequest
        )
        .assertEquals(
          VaultSecret(
            CertificateData(
              certificate,
              issuing_ca,
              List(ca_chain),
              private_key,
              private_key_type,
              serial_number
            ),
            leaseDuration.some,
            leaseId.some,
            renewable.some
          )
        )
    }
  }

  test("generateSecret works as expected when receiving a 200 Ok response") {
    PropF.forAllF(VaultArbitraries.validVaultUri, Gen.identifier) {
      (uri, kid) =>
        Vault
          .generateSecret[IO, SelfManaged, SelfManaged](mockClient, uri)(
            clientToken,
            s"secret/selfmanaged/200/$kid",
            SelfManaged(privateKey, kid)
          )
          .assertEquals(
            VaultSecret(
              SelfManaged(privateKey, kid),
              leaseDuration.some,
              leaseId.some,
              renewable.some
            )
          )
    }
  }

  test(
    "generateSecret works as expected when receiving a 200 Ok with an unparsable response"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri, Gen.identifier) {
      (uri, kid) =>
        Vault
          .generateSecret[IO, SelfManaged, VaultKeys](mockClient, uri)(
            clientToken,
            s"secret/selfmanaged/200/$kid",
            SelfManaged(privateKey, kid)
          )
          .redeem(
            error =>
              if (error.getMessage.contains(privateKey))
                PropF
                  .falsified[IO]
                  .label(s"Secret data in: ${error.getMessage}")
              else PropF.passed[IO].label("Secret data redacted"),
            _ => PropF.falsified[IO].label("Data should not be parseable")
          )
    }
  }

  test(
    "generateSecret works as expected when receiving a 204 No Content response"
  ) {
    PropF.forAllF(VaultArbitraries.validVaultUri, Gen.identifier) {
      (uri, kid) =>
        Vault
          .generateSecret[IO, SelfManaged, SelfManaged](mockClient, uri)(
            clientToken,
            s"secret/selfmanaged/204/$kid",
            SelfManaged(privateKey, kid)
          )
          .assertEquals(
            VaultSecret(
              SelfManaged(privateKey, kid),
              leaseDuration.some,
              leaseId.some,
              renewable.some
            )
          )
    }
  }

  test("generateSecret works as expected when receiving a 4xx response") {
    PropF.forAllF(VaultArbitraries.validVaultUri, Gen.identifier) {
      (uri, kid) =>
        Vault
          .generateSecret[IO, SelfManaged, SelfManaged](mockClient, uri)(
            clientToken,
            s"secret/selfmanaged/4xx/$kid",
            SelfManaged(privateKey, kid)
          )
          .redeem(
            error =>
              if (error.getMessage.contains(privateKey))
                PropF
                  .falsified[IO]
                  .label(s"Secret data in: ${error.getMessage}")
              else PropF.passed[IO].label("Secret data redacted"),
            _ => PropF.falsified[IO].label("Data should not be parseable")
          )
    }
  }

  test(
    "loginAndKeepSecretLeased fails when wait duration is longer than lease duration"
  ) {
    PropF.forAllF(
      VaultArbitraries.validVaultUri,
      Arbitrary.arbitrary[FiniteDuration],
      Arbitrary.arbitrary[FiniteDuration]
    ) { case (uri, leaseDuration, waitInterval) =>
      PropF.boolean[IO](leaseDuration < waitInterval) ==> {

        (Vault
          .loginAndKeepSecretLeased[IO, Unit](mockClient, uri)(
            validRoleId,
            "",
            leaseDuration,
            waitInterval
          ): @nowarn()).attempt.compile.last
          .assertEquals(
            Some(
              Left(
                Vault.InvalidRequirement(
                  "waitInterval longer than requested Lease Duration"
                )
              )
            )
          )
      }
    }
  }
  test(
    "loginK8sAndKeepSecretLeased fails when wait duration is longer than lease duration"
  ) {
    PropF.forAllF(
      VaultArbitraries.validVaultUri,
      Arbitrary.arbitrary[FiniteDuration],
      Arbitrary.arbitrary[FiniteDuration]
    ) { case (uri, leaseDuration, waitInterval) =>
      PropF.boolean[IO](leaseDuration < waitInterval) ==> {

        (Vault
          .loginK8sAndKeepSecretLeased[IO, Unit](mockClient, uri)(
            validRoleId,
            validKubernetesJwt,
            "",
            leaseDuration,
            waitInterval
          ): @nowarn()).attempt.compile.last
          .assertEquals(
            Some(
              Left(
                Vault.InvalidRequirement(
                  "waitInterval longer than requested Lease Duration"
                )
              )
            )
          )
      }
    }
  }
}
