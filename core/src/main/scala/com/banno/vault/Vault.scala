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

import fs2.Stream
import cats._
import cats.effect._
import cats.syntax.all._
import com.banno.vault.models.{CertificateData, CertificateRequest, VaultRequestError, VaultSecret, VaultSecretRenewal, VaultToken, VaultKeys}
import io.circe.{Decoder, DecodingFailure, Encoder, Json}
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.client._
import org.http4s.implicits._
import org.typelevel.ci.CIString


import scala.concurrent.duration._

object Vault {

  /**
   * https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
   */
  def login[F[_]](client: Client[F], vaultUri: Uri): VaultLoginOperation[F] = {
    VaultLoginOperationImpl(client, vaultUri)
  }


  /**
    * https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    *
    * @param mountPoint The mount point of the Kubernetes auth method.
    * Should start with a slash.
    */
  def loginKubernetes[F[_]](client: Client[F], vaultUri: Uri)(role: String, jwt: String, mountPoint: Uri.Path = path"/auth/kubernetes")(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
        method = Method.POST,
        uri = vaultUri.withPath(path"/v1" |+| mountPoint |+| path"/login")
      ).withEntity(
        Json.obj(
          ("role", Json.fromString(role)),
          ("jwt", Json.fromString(jwt))
        ))
    for {
      json <- F.handleErrorWith(client.expect[Json](request)) { e =>
        F.raiseError(VaultRequestError(request, e.some, s"role=$role".some)) //don't expose jwt in error
      }
      token <- raiseKnownError(json.hcursor.get[VaultToken]("auth"))(decoderError)
    } yield token
  }

  /**
   *  https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    */
  @deprecated("Use loginKubernetes, which parameterizes the mount point", "7.1.2")
  def kubernetesLogin[F[_]](client: Client[F], vaultUri: Uri)(role: String, jwt: String)(implicit F: Concurrent[F]): F[VaultToken] =
    loginKubernetes(client, vaultUri)(role, jwt)

  /**
   *  https://www.vaultproject.io/api/secret/kv/index.html#read-secret
   */
  def readSecret[F[_], A](client: Client[F], vaultUri: Uri)(token: String, secretPath: String)(implicit F: Concurrent[F], D: Decoder[A]): F[VaultSecret[A]] = {
    val newSecretPath = if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
      method = Method.GET,
      uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )
    F.adaptError(client.expect[VaultSecret[A]](request)(jsonOf[F, VaultSecret[A]])) {
      case InvalidMessageBodyFailure(_, Some(cause: DecodingFailure)) =>
        InvalidMessageBodyFailure("Could not decode secret key value", cause.some)
    }.handleErrorWith { e =>
      F.raiseError(VaultRequestError(request = request, cause = e.some, extra = s"tokenLength=${token.length}".some))
    }
  }

 /**
   *  https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets uses GET alternative https://www.vaultproject.io/api-docs#api-operations vs LIST
   */
  def listSecrets[F[_]](client: Client[F], vaultUri: Uri)(token: String, secretPath: String)(implicit F: Concurrent[F]): F[VaultKeys] = {
    val newSecretPath = if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
        method = Method.GET,
        uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")).withQueryParam("list", "true"),
        headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
      )
    F.adaptError(client.expect[VaultKeys](request)(jsonOf[F, VaultKeys])) {
      case InvalidMessageBodyFailure(_, Some(cause: DecodingFailure)) =>
        InvalidMessageBodyFailure("Could not decode vault list secrets response", cause.some)
      case e => VaultRequestError(request = request, cause = e.some, extra = s"tokenLength=${token.length}".some)
    }
  }

  /**
   *  https://www.vaultproject.io/api/system/leases.html#renew-lease
   */
  def renewLease[F[_]](client: Client[F], vaultUri: Uri)(leaseId: String, newLeaseDuration: FiniteDuration, token: String)(implicit F: Concurrent[F]): F[VaultSecretRenewal] = {
    val request = Request[F](
        method = Method.PUT,
        uri = vaultUri.withPath(Uri.Path.unsafeFromString("/v1/sys/leases/renew")),
        headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
      ).withEntity(
        Json.obj(
          ("lease_id", Json.fromString(leaseId)),
          ("increment", Json.fromLong(newLeaseDuration.toSeconds))
        )
      )
    for {
      renewal <- F.handleErrorWith(client.expect[VaultSecretRenewal](request)(jsonOf[F, VaultSecretRenewal])) { e =>
        F.raiseError(VaultRequestError(request = request, cause = e.some, extra = s"tokenLength=${token.length}".some))
      }
    } yield renewal
  }

  /**
   *  https://www.vaultproject.io/api/auth/token/index.html#renew-a-token-self-
   */
  def renewSelfToken[F[_]](client: Client[F], vaultUri: Uri)(token: VaultToken, newLeaseDuration: FiniteDuration)(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
        method = Method.POST,
        uri = vaultUri / "v1" / "auth" / "token" / "renew-self",
        headers = Headers(Header.Raw(CIString("X-Vault-Token"), token.clientToken))
      ).withEntity(
        Json.obj(
          ("increment", Json.fromString(s"${newLeaseDuration.toSeconds}s"))
        )
      )
    for {
      json <- F.handleErrorWith(client.expect[Json](request)) { e =>
        F.raiseError(VaultRequestError(request, e.some, s"tokenLength=${token.clientToken.length}".some))
      }
      token <- raiseKnownError(json.hcursor.get[VaultToken]("auth"))(decoderError)
    } yield token
  }

  /**
   *  https://www.vaultproject.io/api/auth/token/index.html#revoke-a-token-self-
   */
  def revokeSelfToken[F[_]](client: Client[F], vaultUri: Uri)(token: VaultToken)(implicit F: Concurrent[F]): F[Unit] = {
    val request = Request[F](
        method = Method.POST,
        uri = vaultUri / "v1" / "auth" / "token" / "revoke-self",
        headers = Headers(Header.Raw(CIString("X-Vault-Token"), token.clientToken))
      )
    val resp = client.status(request).ensureOr(UnexpectedStatus(_, request.method, request.uri ))(_.isSuccess) .void
    F.handleErrorWith(resp) { e =>
      F.raiseError(VaultRequestError(request, e.some, s"tokenLength=${token.clientToken.length}".some))
    }
  }

  /**
   *  https://www.vaultproject.io/api/system/leases.html#revoke-lease
   */
  def revokeLease[F[_]](client: Client[F], vaultUri: Uri)(clientToken: String, leaseId: String)(implicit F: Concurrent[F]): F[Unit] = {
    val request = Request[F](
        method = Method.PUT,
        uri = vaultUri.withPath(Uri.Path.unsafeFromString("/v1/sys/leases/revoke")),
        headers = Headers(Header.Raw(CIString("X-Vault-Token"), clientToken))
      ).withEntity( Json.obj( "lease_id" -> Json.fromString(leaseId) ) )
    for {
      _ <- client.status(request)
        .ensureOr(UnexpectedStatus(_, request.method, request.uri) )(_.isSuccess)
        .handleErrorWith { e =>
          F.raiseError(VaultRequestError(request, e.some, s"tokenLength=${clientToken.length}".some))
        }
    } yield ()
  }

  /**
   *  https://www.vaultproject.io/api/secret/pki/index.html#generate-certificate
   */
  def generateCertificate[F[_]](client: Client[F], vaultUri: Uri)(token: String, secretPath: String, payload: CertificateRequest)(implicit F: Concurrent[F]): F[VaultSecret[CertificateData]] =
    generateSecret(client, vaultUri)(token, secretPath, payload)

  def generateSecret[F[_], A: Encoder, B: Decoder](client: Client[F], vaultUri: Uri)(token: String, secretPath: String, payload: A)(implicit F: Concurrent[F]): F[VaultSecret[B]] = {
    val newSecretPath = if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request =  Request[F](
      method = Method.POST,
      uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )
    val withBody = request.withEntity(payload.asJson)
    for {
      secret   <- F.handleErrorWith(client.expect[VaultSecret[B]](withBody)(jsonOf[F, VaultSecret[B]])) { e =>
        F.raiseError(VaultRequestError(request = withBody, cause = e.some, extra = s"tokenLength=${token.length}".some))
      }
    } yield secret
  }

  /**
    * This function logs in, requests a secret and then continually asks for a duration extension of the lease after
    * each waitInterval
    */
  def keepLoginAndSecretLeased[F[_]: Temporal, A: Decoder](client: Client[F], vaultUri: Uri)
                                                (token: VaultToken, secretPath: String, duration: FiniteDuration, waitInterval: FiniteDuration): Stream[F, A] = {
    Alternative[Option].guard(duration > waitInterval).fold(
      Stream.raiseError[F](InvalidRequirement("waitInterval longer than requested Lease Duration"))
    )(_ => Stream.empty[F]) ++
    keepLoginRenewed[F](client, vaultUri)(token, duration).flatMap { clientToken =>
      readSecretAndRetain[F, A](client, vaultUri, clientToken)(secretPath, waitInterval)
    }
  }

  def loginAndKeepSecretLeased[F[_], A](client: Client[F], vaultUri: Uri): VaultLoginAndKeepSecretLeasedOperation[F, A] =
    VaultLoginAndKeepSecretLeasedOperationImpl(client, vaultUri)

  def loginK8sAndKeepSecretLeased[F[_]: Temporal, A: Decoder](client: Client[F], vaultUri: Uri)
                                                (roleId: String, jwt: String,  secretPath: String, duration: FiniteDuration, waitInterval: FiniteDuration,  loginMountPoint: Uri.Path = path"/auth/kubernetes" ): Stream[F, A] =
    Stream.eval(loginKubernetes(client, vaultUri)(roleId, jwt, loginMountPoint)).flatMap(token => keepLoginAndSecretLeased[F, A](client, vaultUri)(token, secretPath, duration, waitInterval))
    

  /**
    * This function logs into the Vault server given by the vaultUri, to obtain a loginToken.
    *  It then also provides a Stream that continuously renews the token when it is about to finish.
    *  - keeps the token constantly renewed
    *  - Upon termination of the Stream (from the using application) revokes the token.
    *    However, any error on revoking the token is ignored.
    */
  def keepLoginRenewed[F[_]](client: Client[F], vaultUri: Uri)
                                (token: VaultToken, tokenLeaseExtension: FiniteDuration)
                                (implicit T: Temporal[F]): Stream[F, String] = {

    def renewOnDuration(token: VaultToken): F[VaultToken] = {
      val waitInterval: Long =
        Math.min(token.leaseDuration, tokenLeaseExtension.toSeconds) * 9 / 10
      T.sleep(waitInterval.seconds) *>
        Vault.renewSelfToken(client, vaultUri)(token, tokenLeaseExtension)
    }

    def keep(token: VaultToken): Stream[F, Unit] =
      Stream
        .iterateEval(token)(renewOnDuration)
        .takeThrough(_.renewable)
        .last
        .flatMap(lastRenewal => Stream.sleep(lastRenewal.foldMap(_.leaseDuration).seconds)) ++
        Stream.raiseError[F](NonRenewableToken(token.clientToken))

    def cleanup(token: VaultToken): F[Unit] = revokeSelfToken(client, vaultUri)(token).handleError(_ => ())

    Stream.bracket(token.pure[F])(cleanup).flatMap { token =>
      Stream.emit(token.clientToken).concurrently(keep(token))
    }
  }

  def loginAndKeep[F[_]](client: Client[F], vaultUri: Uri): VaultLoginAndKeepOperation[F] = {
    VaultLoginAndKeepOperationImpl(client, vaultUri)
  }


  /**
    * This function uses the given Vault client, uri, and authenticated token to obtain a secret from Vault.
    *  It then also provides a Stream that continuously renews the lease on that secret, when it is about to finish.
    *  Upon termination of the Stream (from the using application) revokes the token (but any error on revokation is ignored).
    */
  def readSecretAndRetain[F[_], A: Decoder](client: Client[F], vaultUri: Uri, clientToken: String)
                                                   (secretPath: String, leaseExtension: FiniteDuration)
                                                   (implicit T: Temporal[F]): Stream[F, A] = {

    def renewOnDuration(renewal: VaultSecretRenewal): F[VaultSecretRenewal] = {
      val waitInterval: Long =
        Math.min(renewal.leaseDuration, leaseExtension.toSeconds) * 9 / 10
      T.sleep(waitInterval.seconds) *>
        Vault.renewLease(client, vaultUri)(renewal.leaseId, leaseExtension, clientToken)
    }

    def keep(secret: VaultSecret[A]): Stream[F, Unit] =
      secret.renewal.fold[Stream[F, Unit]](Stream.empty)(initRenewal =>
        Stream
          .iterateEval(initRenewal)(renewOnDuration)
          .takeThrough(_.renewable)
          .last
          .flatMap(lastRenewal => Stream.sleep(lastRenewal.foldMap(_.leaseDuration).seconds)) ++
          Stream.raiseError[F](NonRenewableSecret(initRenewal.leaseId))
      )

    val read = Vault.readSecret[F, A](client, vaultUri)(clientToken, secretPath)

    def cleanup(secret: VaultSecret[A]): F[Unit] =
      secret.renewal.fold[F[Unit]](
        Applicative[F].unit
      ){renewal =>
        Vault.revokeLease[F](client, vaultUri)(clientToken, renewal.leaseId).handleError(_ => ())
      }


    Stream.bracket(read)(cleanup).flatMap { secret =>
      Stream.emit(secret.data).concurrently(keep(secret))
    }
  }

  private[this] val decoderError: DecodingFailure => DecodeFailure =
    failure => InvalidMessageBodyFailure(s"Could not decode JSON, error: ${failure.message}, cursor: ${failure.history}")

  private[this] def raiseKnownError[F[_], E1, E2 <: Throwable, A](e: Either[E1, A])(errorF: E1 => E2)(implicit F: Concurrent[F]): F[A] =
    F.fromEither(e.leftMap(errorF))

  final case class InvalidRequirement(message: String) extends Throwable {
    override def getMessage(): String = message
  }

  final case class NonRenewableSecret(leaseId: String) extends Throwable {
    override def getMessage(): String = s"Secret lease $leaseId could not be renewed any longer"
  }

  final case class NonRenewableToken(leaseId: String) extends Throwable {
    override def getMessage(): String = s"Token lease $leaseId could not be renewed any longer"
  }

  trait VaultLoginOperation[F[_]] {
    def withRoleSecretId(roleSecretId: String): VaultLoginOperation[F]
    def apply(roleId: String)(implicit F: Concurrent[F]): F[VaultToken]
  }

  final case class VaultLoginOperationImpl[F[_]](client: Client[F], vaultUri: Uri, roleSecretId: Option[String] = None) extends VaultLoginOperation[F] {
    override def withRoleSecretId(roleSecretId: String): VaultLoginOperation[F] = copy(roleSecretId = Some(roleSecretId))
    override def apply(roleId: String)(implicit F: Concurrent[F]): F[VaultToken] = {
      val request = Request[F](
        method = Method.POST,
        uri = vaultUri / "v1" / "auth" / "approle" / "login"
      ).withEntity(
        Json.fromFields(
          Seq("role_id" -> Json.fromString(roleId)) ++
            roleSecretId.fold(Seq[(String, Json)]())(sId => Seq("secret_id" -> Json.fromString(sId)))
        )
      )
      for {
        json <- F.handleErrorWith(client.expect[Json](request)
        ) { e =>
          F.raiseError(VaultRequestError(request, e.some, s"roleId=$roleId, roleSecretId=$roleSecretId".some))
        }
        token <- raiseKnownError(json.hcursor.get[VaultToken]("auth"))(decoderError)
      } yield token
    }
  }

  trait VaultLoginAndKeepOperation[F[_]] {
    def withRoleSecretId(roleSecretId: String): VaultLoginAndKeepOperation[F]
    def apply(roleId: String, tokenLeaseExtension: FiniteDuration)(implicit A: Async[F]): Stream[F, String]
  }

  final case class VaultLoginAndKeepOperationImpl[F[_]](client: Client[F], vaultUri: Uri, roleSecretId: Option[String] = None) extends VaultLoginAndKeepOperation[F] {
    override def withRoleSecretId(roleSecretId: String): VaultLoginAndKeepOperation[F] = copy(roleSecretId = Some(roleSecretId))
    def apply(roleId: String, tokenLeaseExtension: FiniteDuration)(implicit A: Async[F]): Stream[F, String] = {
      val loginOperation = login(client, vaultUri)
      Stream.eval(roleSecretId.fold(loginOperation)(loginOperation.withRoleSecretId)(roleId))
        .flatMap(token => keepLoginRenewed[F](client, vaultUri)(token, tokenLeaseExtension))
    }
  }

  trait VaultLoginAndKeepSecretLeasedOperation[F[_], A] {
    def withRoleSecretId(roleSecretId: String): VaultLoginAndKeepSecretLeasedOperation[F, A]
    def apply(roleId: String, secretPath: String, duration: FiniteDuration, waitInterval: FiniteDuration)(implicit T: Temporal[F], D: Decoder[A]): Stream[F, A]
  }

  final case class VaultLoginAndKeepSecretLeasedOperationImpl[F[_], A](client: Client[F], vaultUri: Uri, roleSecretId: Option[String] = None) extends VaultLoginAndKeepSecretLeasedOperation[F, A] {
    override def withRoleSecretId(roleSecretId: String): VaultLoginAndKeepSecretLeasedOperation[F, A] = copy(roleSecretId = Some(roleSecretId))
    override def apply(roleId: String, secretPath: String, duration: FiniteDuration, waitInterval: FiniteDuration)(implicit T: Temporal[F], D: Decoder[A]): Stream[F, A] = {
      val loginOperation = login(client, vaultUri)
      Stream.eval(roleSecretId.fold(loginOperation)(loginOperation.withRoleSecretId)(roleId))
        .flatMap(token => keepLoginAndSecretLeased[F, A](client, vaultUri)(token, secretPath, duration, waitInterval))
    }
  }

}
