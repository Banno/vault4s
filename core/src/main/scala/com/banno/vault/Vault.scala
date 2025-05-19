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

import cats.*
import cats.effect.*
import cats.syntax.all.*
import com.banno.vault.models.*
import fs2.Stream
import io.circe.syntax.*
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.*
import org.http4s.implicits.*
import org.typelevel.ci.CIString

import scala.concurrent.duration.*

/** Helper methods for working with Vault
  *
  * @note
  *   The implementations here are mostly correct (with the exception of
  *   deprecated methods) however they do not handle token lifecycle or retries
  *   (Vault is eventually consistent, and when inconsistency is detected, they
  *   return `412 Precondition Failed` instead of the stale value).
  *
  * @note
  *   Consider using the more modern [[VaultClient]] for better ergonomics,
  *   lifecycle management, and retries.
  */
object Vault {

  /** https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    */
  def login[F[_]](client: Client[F], vaultUri: Uri)(
      roleId: String
  )(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "approle" / "login"
    ).withEntity(Json.obj(("role_id", Json.fromString(roleId))))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"roleId=$roleId".some
    )
  }

  /** https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    */
  def loginAppRoleAndSecretId[F[_]](client: Client[F], vaultUri: Uri)(
      roleId: String,
      secretId: String
  )(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "approle" / "login"
    ).withEntity(
      Json.obj(
        "role_id" := roleId,
        "secret_id" := secretId
      )
    )

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"roleId=$roleId, secretId=XXXX".some
    )
  }

  /** https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    *
    * @param mountPoint
    *   The mount point of the Kubernetes auth method. Should start with a
    *   slash.
    */
  def loginKubernetes[F[_]](client: Client[F], vaultUri: Uri)(
      role: String,
      jwt: String,
      mountPoint: Uri.Path = path"/auth/kubernetes"
  )(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri.withPath(path"/v1" |+| mountPoint |+| path"/login")
    ).withEntity(
      Json.obj(
        ("role", Json.fromString(role)),
        ("jwt", Json.fromString(jwt))
      )
    )

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"role=$role".some // don't expose jwt in error
    )
  }

  /** https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    */
  @deprecated(
    "Use loginKubernetes, which parameterizes the mount point",
    "7.1.2"
  )
  def kubernetesLogin[F[_]](client: Client[F], vaultUri: Uri)(
      role: String,
      jwt: String
  )(implicit F: Concurrent[F]): F[VaultToken] =
    loginKubernetes(client, vaultUri)(role, jwt)

  /** https://developer.hashicorp.com/vault/docs/auth/github
    */
  def loginGitHub[F[_]](client: Client[F], vaultUri: Uri)(
      token: String
  )(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "github" / "login"
    ).withEntity(Json.obj(("token", Json.fromString(token))))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      none // don't expose token in error
    )
  }

  /** https://developer.hashicorp.com/vault/api-docs/auth/userpass
    */
  def loginUserPass[F[_]](client: Client[F], vaultUri: Uri)(
      username: String,
      password: String
  )(implicit F: Concurrent[F]): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "userpass" / "login" / username
    ).withEntity(Json.obj("password" := password))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"username=$username".some // don't expose password in error
    )
  }

  /** https://www.vaultproject.io/api/secret/kv/index.html#read-secret
    */
  def readSecret[F[_], A](client: Client[F], vaultUri: Uri)(
      token: String,
      secretPath: String
  )(implicit F: Concurrent[F], D: Decoder[A]): F[VaultSecret[A]] = {
    val newSecretPath =
      if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
      method = Method.GET,
      uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )

    decodeResponseOrFail[F, VaultSecret[A]](
      request,
      client.run(request),
      _.hcursor,
      s"tokenLength=${token.length}".some,
      df =>
        InvalidMessageBodyFailure("Could not decode secret key value", df.some)
    )
  }

  /** https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets uses GET
    * alternative https://www.vaultproject.io/api-docs#api-operations vs LIST
    */
  def listSecrets[F[_]](client: Client[F], vaultUri: Uri)(
      token: String,
      secretPath: String
  )(implicit F: Concurrent[F]): F[VaultKeys] = {
    val newSecretPath =
      if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
      method = Method.GET,
      uri = vaultUri
        .withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath"))
        .withQueryParam("list", "true"),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )

    decodeResponseOrFail[F, VaultKeys](
      request,
      client.run(request),
      _.hcursor,
      s"tokenLength=${token.length}".some,
      df =>
        InvalidMessageBodyFailure(
          "Could not decode vault list secrets response",
          df.some
        )
    )
  }

  /** https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#delete-secret
    */
  def deleteSecret[F[_]](client: Client[F], vaultUri: Uri)(
      token: String,
      secretPath: String
  )(implicit F: Concurrent[F]): F[Unit] = {
    val newSecretPath =
      if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
      method = Method.DELETE,
      uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )

    client
      .run(request)
      .use(expectSuccessOrFail(request, _, s"tokenLength=${token.length}".some))
  }

  /** https://www.vaultproject.io/api/system/leases.html#renew-lease
    */
  def renewLease[F[_]](client: Client[F], vaultUri: Uri)(
      leaseId: String,
      newLeaseDuration: FiniteDuration,
      token: String
  )(implicit F: Concurrent[F]): F[VaultSecretRenewal] = {
    val request = Request[F](
      method = Method.PUT,
      uri =
        vaultUri.withPath(Uri.Path.unsafeFromString("/v1/sys/leases/renew")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    ).withEntity(
      Json.obj(
        ("lease_id", Json.fromString(leaseId)),
        ("increment", Json.fromLong(newLeaseDuration.toSeconds))
      )
    )

    decodeResponseOrFail[F, VaultSecretRenewal](
      request,
      client.run(request),
      _.hcursor,
      s"tokenLength=${token.length}".some,
      df =>
        InvalidMessageBodyFailure(
          "Could not decode vault lease renew response",
          df.some
        )
    )
  }

  /** https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token-self
    */
  def renewSelfToken[F[_]](client: Client[F], vaultUri: Uri)(
      token: VaultToken,
      newLeaseDuration: FiniteDuration
  )(implicit F: Concurrent[F]): F[VaultToken] =
    if (!token.renewable)
      NonRenewableToken(token.clientToken).raiseError[F, VaultToken]
    else {
      val request = Request[F](
        method = Method.POST,
        uri = vaultUri / "v1" / "auth" / "token" / "renew-self",
        headers =
          Headers(Header.Raw(CIString("X-Vault-Token"), token.clientToken))
      ).withEntity(
        Json.obj(
          ("increment", Json.fromString(s"${newLeaseDuration.toSeconds}s"))
        )
      )

      decodeResponseOrFail[F, VaultToken](
        request,
        client.run(request),
        _.hcursor.downField("auth"),
        s"tokenLength=${token.clientToken.length}".some,
        df =>
          InvalidMessageBodyFailure(
            "Could not decode vault token renew response",
            df.some
          )
      )
    }

  /** https://www.vaultproject.io/api/auth/token/index.html#revoke-a-token-self-
    */
  def revokeSelfToken[F[_]](client: Client[F], vaultUri: Uri)(
      token: VaultToken
  )(implicit F: Concurrent[F]): F[Unit] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "token" / "revoke-self",
      headers =
        Headers(Header.Raw(CIString("X-Vault-Token"), token.clientToken))
    )

    client
      .run(request)
      .use(
        expectSuccessOrFail(
          request,
          _,
          s"tokenLength=${token.clientToken.length}".some
        )
      )
  }

  /** https://www.vaultproject.io/api/system/leases.html#revoke-lease
    */
  def revokeLease[F[_]](client: Client[F], vaultUri: Uri)(
      clientToken: String,
      leaseId: String
  )(implicit F: Concurrent[F]): F[Unit] = {
    val request = Request[F](
      method = Method.PUT,
      uri =
        vaultUri.withPath(Uri.Path.unsafeFromString("/v1/sys/leases/revoke")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), clientToken))
    ).withEntity(Json.obj("lease_id" -> Json.fromString(leaseId)))

    client
      .run(request)
      .use(
        expectSuccessOrFail(
          request,
          _,
          s"tokenLength=${clientToken.length}".some
        )
      )
  }

  /** https://www.vaultproject.io/api/secret/pki/index.html#generate-certificate
    */
  def generateCertificate[F[_]](
      client: Client[F],
      vaultUri: Uri
  )(token: String, secretPath: String, payload: CertificateRequest)(implicit
      F: Concurrent[F]
  ): F[VaultSecret[CertificateData]] =
    generateSecret(client, vaultUri)(token, secretPath, payload)

  def generateSecret[F[_], A: Encoder, B: Decoder](
      client: Client[F],
      vaultUri: Uri
  )(token: String, secretPath: String, payload: A)(implicit
      F: Concurrent[F]
  ): F[VaultSecret[B]] = {
    val newSecretPath =
      if (secretPath.startsWith("/")) secretPath.substring(1) else secretPath
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri.withPath(Uri.Path.unsafeFromString(s"/v1/$newSecretPath")),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )

    decodeResponseOrFailOpt[F, VaultSecret[B]](
      request,
      client.run(request.withEntity(payload.asJson)),
      _.hcursor,
      s"tokenLength=${token.length}".some,
      df =>
        InvalidMessageBodyFailure("Could not decode secret key value", df.some)
    ).flatMap {
      case Some(vs) => vs.pure[F]
      case None =>
        readSecret[F, B](client, vaultUri)(token, secretPath)
          .adaptError { case readError =>
            readError.addSuppressed(
              UnexpectedStatus(Status.NoContent, request.method, request.uri)
            )
            VaultRequestError(
              request = request,
              cause = readError.some,
              extra = s"tokenLength=${token.length}".some
            )
          }
    }
  }

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience or replace this with [[Vault.readSecret]].
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <h2>CAUTION: Vault secret leases</h2>
    *
    * This method fundamentally misunderstands how V1 secret leases work in
    * Vault. They aren't leases which invalidate the secret when they expire,
    * they're cache hints that suggest how long to wait before checking if the
    * value has changed.
    *
    * There's no functional difference between using this method and simply
    * reading the secret once.
    *
    * <hr/>
    *
    * This function logs in, requests a secret and then continually asks for a
    * duration extension of the lease after each waitInterval
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def keepLoginAndSecretLeased[F[_]: Temporal, A: Decoder](
      client: Client[F],
      vaultUri: Uri
  )(
      token: VaultToken,
      secretPath: String,
      duration: FiniteDuration,
      waitInterval: FiniteDuration
  ): Stream[F, A] = {
    Alternative[Option]
      .guard(duration > waitInterval)
      .fold(
        Stream.raiseError[F](
          InvalidRequirement(
            "waitInterval longer than requested Lease Duration"
          )
        )
      )(_ => Stream.empty[F]) ++
      keepLoginRenewed[F](client, vaultUri)(token, duration).flatMap {
        clientToken =>
          readSecretAndRetain[F, A](client, vaultUri, clientToken)(
            secretPath,
            waitInterval
          )
      }
  }

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience or replace this with [[Vault.readSecret]].
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <h2>CAUTION: Vault secret leases</h2>
    *
    * This method fundamentally misunderstands how V1 secret leases work in
    * Vault. They aren't leases which invalidate the secret when they expire,
    * they're cache hints that suggest how long to wait before checking if the
    * value has changed.
    *
    * There's no functional difference between using this method and simply
    * reading the secret once.
    *
    * <hr/>
    *
    * This function logs in, requests a secret and then continually asks for a
    * duration extension of the lease after each waitInterval
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def loginAndKeepSecretLeased[F[_]: Temporal, A: Decoder](
      client: Client[F],
      vaultUri: Uri
  )(
      roleId: String,
      secretPath: String,
      duration: FiniteDuration,
      waitInterval: FiniteDuration
  ): Stream[F, A] =
    Stream
      .eval(login(client, vaultUri)(roleId))
      .flatMap(token =>
        keepLoginAndSecretLeased[F, A](client, vaultUri)(
          token,
          secretPath,
          duration,
          waitInterval
        )
      )

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience or replace this with [[Vault.readSecret]].
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <h2>CAUTION: Vault secret leases</h2>
    *
    * This method fundamentally misunderstands how V1 secret leases work in
    * Vault. They aren't leases which invalidate the secret when they expire,
    * they're cache hints that suggest how long to wait before checking if the
    * value has changed.
    *
    * There's no functional difference between using this method and simply
    * reading the secret once.
    *
    * <hr/>
    *
    * This function logs in, requests a secret and then continually asks for a
    * duration extension of the lease after each waitInterval
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def loginK8sAndKeepSecretLeased[F[_]: Temporal, A: Decoder](
      client: Client[F],
      vaultUri: Uri
  )(
      roleId: String,
      jwt: String,
      secretPath: String,
      duration: FiniteDuration,
      waitInterval: FiniteDuration,
      loginMountPoint: Uri.Path = path"/auth/kubernetes"
  ): Stream[F, A] =
    Stream
      .eval(loginKubernetes(client, vaultUri)(roleId, jwt, loginMountPoint))
      .flatMap(token =>
        keepLoginAndSecretLeased[F, A](client, vaultUri)(
          token,
          secretPath,
          duration,
          waitInterval
        )
      )

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience.
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <hr/>
    *
    * This function continually asks for a duration extension of the token after
    * each waitInterval
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def keepLoginRenewed[F[_]](client: Client[F], vaultUri: Uri)(
      token: VaultToken,
      tokenLeaseExtension: FiniteDuration
  )(implicit T: Temporal[F]): Stream[F, String] = {

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
        .flatMap(lastRenewal =>
          Stream.sleep(lastRenewal.foldMap(_.leaseDuration).seconds)
        ) ++
        Stream.raiseError[F](NonRenewableToken(token.clientToken))

    def cleanup(token: VaultToken): F[Unit] =
      revokeSelfToken(client, vaultUri)(token).handleError(_ => ())

    Stream.bracket(token.pure[F])(cleanup).flatMap { token =>
      Stream.emit(token.clientToken).concurrently(keep(token))
    }
  }

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience.
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <hr/>
    *
    * This function logs in and then continually asks for a duration extension
    * of the token after each waitInterval
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def loginAndKeep[F[_]: Async](
      client: Client[F],
      vaultUri: Uri
  )(roleId: String, tokenLeaseExtension: FiniteDuration): Stream[F, String] =
    Stream
      .eval(login(client, vaultUri)(roleId))
      .flatMap(token =>
        keepLoginRenewed[F](client, vaultUri)(token, tokenLeaseExtension)
      )

  /** <h1>WARNING: This method is deeply flawed.</h1>
    *
    * Don't panic, and please migrate to [[VaultClient]] at your earliest
    * convenience or replace this with [[Vault.readSecret]].
    *
    * <h2>CAUTION: `fs2.Stream` abuse</h2>
    *
    * `fs2.Stream` is entirely the wrong effect type to model what is happening
    * here, because of this there was a long-standing bug where it could
    * immediately revoke the token.
    *
    * There isn't really a fix for this, because the root issue is
    * [[fs2.Stream.concurrently]] doesn't seem to compose with
    * [[fs2.Stream.ToPull.uncons]]. This issue was noticed back in
    * [[https://github.com/typelevel/fs2/issues/3123 February 2023]], and at
    * time of writing is still open.
    *
    * <h3>Mitigation</h3>
    *
    * If possible, migrate to [[VaultClient]]. If this is not possible, try to
    * avoid doing anything fancy to your [[fs2.Stream]] between when this method
    * is called and when it is used.
    *
    * A non-comprehensive list of methods to avoid:
    *
    * <ul>
    *
    * <li>Any variation of [[fs2.Stream.ToPull.uncons]]</li>
    *
    * <li>Any variation of [[fs2.Stream.drop]]</li>
    *
    * <li>Any variation of [[fs2.Stream.take]]</li>
    *
    * <li>Any variation of [[fs2.Stream.hold]]</li>
    *
    * <li>[[fs2.Stream.resource]] and other methods which return a
    * [[cats.effect.Resource]]</li>
    *
    * <li>[[fs2.Stream.drain]]</li>
    *
    * </ul>
    *
    * <h2>CAUTION: Vault secret leases</h2>
    *
    * This method fundamentally misunderstands how V1 secret leases work in
    * Vault. They aren't leases which invalidate the secret when they expire,
    * they're cache hints that suggest how long to wait before checking if the
    * value has changed.
    *
    * There's no functional difference between using this method and simply
    * reading the secret once.
    *
    * <hr/>
    *
    * This function uses the given Vault client, uri, and authenticated token to
    * obtain a secret from Vault. It then also provides a Stream that
    * continuously renews the lease on that secret, when it is about to finish.
    * Upon termination of the Stream (from the using application) revokes the
    * token (but any error on revocation is ignored).
    */
  @deprecated(
    message = "Deprecated in favor of VaultClient, see scaladoc for details",
    since = "9.3.0"
  )
  def readSecretAndRetain[F[_], A: Decoder](
      client: Client[F],
      vaultUri: Uri,
      clientToken: String
  )(secretPath: String, leaseExtension: FiniteDuration)(implicit
      T: Temporal[F]
  ): Stream[F, A] = {

    def renewOnDuration(renewal: VaultSecretRenewal): F[VaultSecretRenewal] = {
      val waitInterval: Long =
        Math.min(renewal.leaseDuration, leaseExtension.toSeconds) * 9 / 10
      T.sleep(waitInterval.seconds) *>
        Vault.renewLease(client, vaultUri)(
          renewal.leaseId,
          leaseExtension,
          clientToken
        )
    }

    def keep(secret: VaultSecret[A]): Stream[F, Unit] =
      secret.renewal.fold[Stream[F, Unit]](Stream.empty)(initRenewal =>
        Stream
          .iterateEval(initRenewal)(renewOnDuration)
          .takeThrough(_.renewable)
          .last
          .flatMap(lastRenewal =>
            Stream.sleep(lastRenewal.foldMap(_.leaseDuration).seconds)
          ) ++
          Stream.raiseError[F](NonRenewableSecret(initRenewal.leaseId))
      )

    val read = Vault.readSecret[F, A](client, vaultUri)(clientToken, secretPath)

    def cleanup(secret: VaultSecret[A]): F[Unit] =
      secret.renewal.fold[F[Unit]](
        Applicative[F].unit
      ) { renewal =>
        Vault
          .revokeLease[F](client, vaultUri)(clientToken, renewal.leaseId)
          .handleError(_ => ())
      }

    Stream.bracket(read)(cleanup).flatMap { secret =>
      Stream.emit(secret.data).concurrently(keep(secret))
    }
  }

  private[this] val decoderError: DecodingFailure => DecodeFailure =
    failure =>
      InvalidMessageBodyFailure(
        s"Could not decode JSON, error: ${failure.message}, cursor: ${failure.history}"
      )

  private[this] def decodeResponseOrFailOpt[F[_]: Concurrent, A: Decoder](
      request: Request[F],
      responseR: Resource[F, Response[F]],
      toCursor: Json => ACursor,
      extra: Option[String],
      fmtDecoderFailure: DecodingFailure => DecodeFailure
  ): F[Option[A]] =
    responseR.use { response =>
      if (response.status === Status.NoContent)
        none.pure[F]
      else if (response.status.isSuccess)
        response.json
          .adaptError { case e => VaultRequestError(request, e.some, extra) }
          .flatMap { json =>
            toCursor(json)
              .as[A]
              .leftFlatMap { e =>
                VaultApiError
                  .decode(response.status, json)
                  .fold(
                    _ => fmtDecoderFailure(e).asLeft[A],
                    vae =>
                      Left {
                        if (vae.errors.nonEmpty) vae
                        else fmtDecoderFailure(e)
                      }
                  )
              }
              .bimap(
                cause => VaultRequestError(request, cause.some, extra),
                _.some
              )
              .liftTo[F]
          }
      else
        response.json.flatMap { json =>
          val cause = VaultApiError
            .decode(response.status, json)
            .valueOr(fmtDecoderFailure(_))

          VaultRequestError(request, cause.some, extra).raiseError[F, Option[A]]
        }
    }

  private[this] def decodeResponseOrFail[F[_]: Concurrent, A: Decoder](
      request: Request[F],
      responseR: Resource[F, Response[F]],
      toCursor: Json => ACursor,
      extra: Option[String],
      fmtDecoderFailure: DecodingFailure => DecodeFailure
  ): F[A] =
    decodeResponseOrFailOpt[F, A](
      request,
      responseR,
      toCursor,
      extra,
      fmtDecoderFailure
    )
      .flatMap(_.liftTo[F] {
        VaultRequestError(
          request,
          UnexpectedStatus(Status.NoContent, request.method, request.uri).some,
          extra
        )
      })

  private[this] def decodeLoginOrFail[F[_]: Concurrent](
      request: Request[F],
      response: Resource[F, Response[F]],
      extra: Option[String]
  ): F[VaultToken] =
    decodeResponseOrFail[F, VaultToken](
      request,
      response,
      _.hcursor.downField("auth"),
      extra,
      decoderError
    )

  private[this] def expectSuccessOrFail[F[_]: Concurrent](
      request: Request[F],
      response: Response[F],
      extra: Option[String]
  ): F[Unit] =
    if (response.status.isSuccess) Applicative[F].unit
    else {
      val unexpectedStatus =
        UnexpectedStatus(response.status, request.method, request.uri)
      response.json
        .adaptError { case e =>
          unexpectedStatus.addSuppressed(e)
          VaultRequestError(request, unexpectedStatus.some, extra)
        }
        .flatMap { json =>
          VaultApiError
            .decode(response.status, json)
            .fold(
              df => {
                unexpectedStatus.addSuppressed(df)
                VaultRequestError(request, unexpectedStatus.some, extra)
              },
              vae => {
                if (vae.errors.nonEmpty)
                  VaultRequestError(request, vae.some, extra)
                else
                  VaultRequestError(request, unexpectedStatus.some, extra)
              }
            )
            .raiseError[F, Unit]
        }
    }

  final case class InvalidRequirement(message: String) extends Throwable {
    override def getMessage(): String = message
  }

  final case class NonRenewableSecret(leaseId: String) extends Throwable {
    override def getMessage(): String =
      s"Secret lease $leaseId could not be renewed any longer"
  }

  final case class NonRenewableToken(leaseId: String) extends Throwable {
    override def getMessage(): String =
      s"Token lease $leaseId could not be renewed any longer"
  }
}
