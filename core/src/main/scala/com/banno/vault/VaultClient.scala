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

import cats.data.NonEmptyChain
import cats.effect.kernel.{RefSource, Resource}
import cats.effect.syntax.all.*
import cats.effect.{Async, Ref, Temporal}
import cats.syntax.all.*
import cats.{Applicative, MonadThrow, NonEmptyParallel, ~>}
import com.banno.vault.Vault.NonRenewableSecret
import com.banno.vault.models.*
import io.circe.{Decoder, Encoder}
import org.http4s.client.{Client, UnexpectedStatus}
import org.http4s.{Status, Uri}

import scala.concurrent.duration.{DurationLong, FiniteDuration}

/** An alternative to [[Vault]] that keeps track of the client, vault URI, and
  * client taken, as well as handling token renewal and retries.
  *
  * @see
  *   https://developer.hashicorp.com/vault/api-docs#api-operations
  *
  * @note
  *   The `/v1` prefix is prepended to all secret paths, and indicates the API
  *   version, not the secret engine version, check your server config if this
  *   distinction matters for your use case. <br/><br/> `VaultClient` is known
  *   to work with the KV1 engine, and may work with the KV2 engine, however
  *   there are a few corner cases when this may not be the case. One example is
  *   the that secret metadata and version capabilities of the KV2 engine are
  *   not currently supported.
  */
trait VaultClient[F[_]] {

  /** Read a secret at a `secretPath` and decode as an `A`
    *
    * <h2>TIP: Vault secret leases and engine types</h2>
    *
    * Most of the secret related methods in [[VaultClient]] implicitly assume
    * the KV1 secret engine
    *
    * KV1 secret engine leases do not invalidate the secret when they expire,
    * they're cache hints that suggest how long to wait before checking if the
    * value has changed.
    *
    * <h3>CAUTION: non-KV2 secrets <i>may</i> expire</h3>
    *
    * Dynamic secrets (like database credentials) are a common example, so if a
    * secret becomes invalid after a set period of time,
    * [[VaultClient.VaultClientExtensions.readSecretAndKeep]] may be what is
    * needed.
    *
    * @note
    *   Despite being a prefix common to all secrets, `secret/` does need to
    *   appear in `secretPath`. `/v1/`, however, should not be included.
    *
    * If a secret resides at `/v1/secret/foo/bar/baz`, then `secretPath` should
    * be `secret/foo/bar/baz`
    *
    * @note
    *   The `/v1` prefix indicates the API version, not the secret engine
    *   version, check your server config if this distinction matters for your
    *   use case.
    *
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret
    */
  def readSecret[A: Decoder](secretPath: String): F[VaultSecret[A]]

  /** Convenience wrapper for `readSecret`, when the renewal information is not
    * needed.
    * @see
    *   [[readSecret]]
    */
  def readSecretData[A: Decoder](secretPath: String): F[A]

  /** @note
    *   Despite being a prefix common to all secrets, `secret/` does need to
    *   appear in `secretPath`. `/v1/`, however, does not need to be included.
    *
    * If a secret resides at `/v1/secret/foo/bar/baz`, then `secretPath` should
    * be `secret/foo/bar/baz`
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#list-secrets
    * @see
    *   https://www.vaultproject.io/api-docs#api-operations to use LIST
    */
  def listSecrets(secretPath: String): F[VaultKeys]

  /** @note
    *   Despite being a prefix common to all secrets, `secret/` does need to
    *   appear in `secretPath`. `/v1/`, however, does not need to be included.
    *
    * If a secret resides at `/v1/secret/foo/bar/baz`, then `secretPath` should
    * be `secret/foo/bar/baz`
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#create-update-secret
    */
  def createSecret[A: Encoder, B: Decoder](
      secretPath: String,
      payload: A
  ): F[VaultSecret[B]]

  /** @note
    *   Despite being a prefix common to all secrets, `secret/` does need to
    *   appear in `secretPath`. `/v1/`, however, does not need to be included.
    *
    * If a secret resides at `/v1/secret/foo/bar/baz`, then `secretPath` should
    * be `secret/foo/bar/baz`
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#delete-secret
    */
  def deleteSecret(secretPath: String): F[Unit]

  /** https://www.vaultproject.io/api/system/leases.html#renew-lease
    */
  def renewLease(
      leaseId: String,
      newLeaseDuration: FiniteDuration
  ): F[VaultSecretRenewal]

  /** https://www.vaultproject.io/api/system/leases.html#revoke-lease
    */
  def revokeLease(leaseId: String): F[Unit]

  /** https://www.vaultproject.io/api/secret/pki/index.html#generate-certificate
    */
  def generateCertificate(
      secretPath: String,
      payload: CertificateRequest
  ): F[VaultSecret[CertificateData]]

  protected def applicative: Applicative[F]

  /** Change the effect type
    */
  def mapK[G[_]: Applicative](fg: F ~> G): VaultClient[G]
}

object VaultClient {

  /** Log in, without attempting to keep it fresh, revoking it when the
    * `Resource` closes.
    *
    * This is useful when you know the token will no longer be needed before the
    * TTL expires
    *
    * @see
    *   https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    * @see
    *   https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token-self
    */
  def loginOnce[F[_]: Async](
      client: Client[F],
      vaultConfig: VaultConfig,
      consistencyConfig: ConsistencyConfig
  ): Resource[F, VaultClient[F]] =
    Resource
      .make(loginWithRetry(client, vaultConfig, consistencyConfig))(
        revokeWithRetry(_, client, vaultConfig, consistencyConfig)
      )
      .map(_.clientToken)
      .evalMap(Ref[F].of(_))
      .map(new Default[F](client, vaultConfig.vaultUri, _, consistencyConfig))

  /** Log in and keep the token fresh, revoking it when the `Resource` closes.
    *
    * @see
    *   https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    * @see
    *   https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    * @see
    *   https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token-self
    */
  def loginAndKeep[F[_]: Async: NonEmptyParallel](
      client: Client[F],
      vaultConfig: VaultConfig,
      consistencyConfig: ConsistencyConfig
  ): Resource[F, VaultClient[F]] = {
    val login: F[VaultToken] =
      loginWithRetry(client, vaultConfig, consistencyConfig)

    def revoke(token: VaultToken): F[Unit] =
      revokeWithRetry(token, client, vaultConfig, consistencyConfig)

    def sleep(token: VaultToken): F[Unit] =
      sleepUntilEarliest[F](
        token.leaseDuration,
        vaultConfig.tokenLeaseExtension.toSeconds
      )

    def renew(token: VaultToken): F[VaultToken] =
      if (token.renewable)
        recoverVaultRequestWithRevokeAndRetry(
          renewWithRetry(token, client, vaultConfig, consistencyConfig),
          revoke(token),
          login
        )
      else
        login

    Resource
      .make(login.flatMap(Ref[F].of(_)))(_.get.flatMap(revoke))
      .flatTap { vaultTokenRef =>
        vaultTokenRef.get
          .flatMap(token => sleep(token) >> renew(token))
          .flatMap(vaultTokenRef.set)
          .foreverM
          .background
      }
      .map(ref => (ref: RefSource[F, VaultToken]).map(_.clientToken))
      .map(new Default[F](client, vaultConfig.vaultUri, _, consistencyConfig))
  }

  private def sleepUntilEarliest[F[_]: Temporal](a: Long, b: Long): F[Unit] = {
    val waitInterval: Long = Math.min(a, b) * 9 / 10

    Temporal[F].sleep(waitInterval.seconds)
  }

  private def retryUntilConsistent[F[_]: Async, A](
      config: ConsistencyConfig,
      attempt: F[A]
  ): F[A] = {
    def loop(retries: Int, errors: NonEmptyChain[Throwable]): F[A] = {
      if (retries <= 0) new CurrentlyInconsistent(errors).raiseError[F, A]
      else
        Async[F].sleep(config.delay) >> attempt.recoverWith {
          case CurrentlyInconsistent(initialError) =>
            loop(retries - 1, errors.append(initialError))
        }
    }

    attempt.recoverWith { case CurrentlyInconsistent(error) =>
      loop(config.retries, NonEmptyChain.one(error))
    }
  }

  private def loginWithRetry[F[_]: Async](
      client: Client[F],
      vaultConfig: VaultConfig,
      leaseConfig: ConsistencyConfig
  ): F[VaultToken] =
    retryUntilConsistent(
      leaseConfig,
      vaultConfig match {
        case role: VaultConfig.AppRole =>
          role.secretId match {
            case None => Vault.login(client, role.vaultUri)(role.roleId)
            case Some(secretId) =>
              Vault.loginAppRoleAndSecretId(client, role.vaultUri)(
                role.roleId,
                secretId
              )
          }
        case k8s: VaultConfig.K8s =>
          Vault.loginKubernetes(client, k8s.vaultUri)(
            k8s.roleId,
            k8s.jwt,
            k8s.mountPoint
          )
        case gitHub: VaultConfig.GitHub =>
          Vault.loginGitHub(client, gitHub.vaultUri)(gitHub.gitHubToken)
        case uap: VaultConfig.UsernameAndPassword =>
          Vault.loginUserPass(client, uap.vaultUri)(uap.username, uap.username)
      }
    )

  private def renewWithRetry[F[_]: Async](
      vaultToken: VaultToken,
      client: Client[F],
      vaultConfig: VaultConfig,
      leaseConfig: ConsistencyConfig
  ): F[VaultToken] =
    retryUntilConsistent(
      leaseConfig,
      Vault.renewSelfToken(client, vaultConfig.vaultUri)(
        vaultToken,
        vaultConfig.tokenLeaseExtension
      )
    )

  private def revokeWithRetry[F[_]: Async](
      vaultToken: VaultToken,
      client: Client[F],
      vaultConfig: VaultConfig,
      leaseConfig: ConsistencyConfig
  ): F[Unit] =
    retryUntilConsistent(
      leaseConfig,
      Vault.revokeSelfToken(client, vaultConfig.vaultUri)(vaultToken)
    ).recoverWith {
      case VaultRequestError(
            _,
            Some(
              UnexpectedStatus(Status.Forbidden, _, _) |
              VaultApiError(Status.Forbidden, _)
            )
          ) =>
        // This means the token has already expired or been revoked, so we can ignore this
        Async[F].unit
    }

  private def recoverVaultRequestWithRevokeAndRetry[F[
      _
  ]: MonadThrow: NonEmptyParallel, A](
      initial: F[A],
      revoke: F[Unit],
      retry: F[A]
  ): F[A] =
    initial.recoverWith { case vre: VaultRequestError =>
      (revoke.attempt, retry.attempt).parFlatMapN {
        case (_, Right(a)) => a.pure[F]
        case (Right(_), Left(retryError)) =>
          if (!(vre eq retryError)) {
            vre.addSuppressed(retryError)
          }
          vre.raiseError[F, A]
        case (Left(revokeError), Left(retryError)) =>
          if (!(vre eq revokeError)) {
            vre.addSuppressed(revokeError)
          }
          if (!(vre eq retryError)) {
            vre.addSuppressed(retryError)
          }
          vre.raiseError[F, A]
      }
    }

  private class Default[F[_]: Async](
      client: Client[F],
      vaultUri: Uri,
      tokenRef: RefSource[F, String],
      consistencyConfig: ConsistencyConfig
  ) extends VaultClient[F] {
    override protected def applicative: Applicative[F] = Async[F]

    private def retryOnPreconditionFailed[A](fa: F[A]): F[A] =
      retryUntilConsistent(consistencyConfig, fa)

    override def readSecret[A: Decoder](secretPath: String): F[VaultSecret[A]] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault.readSecret[F, A](client, vaultUri)(_, secretPath)
        )
      }

    override def readSecretData[A: Decoder](secretPath: String): F[A] =
      readSecret[A](secretPath).map(_.data)

    override def listSecrets(secretPath: String): F[VaultKeys] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault.listSecrets[F](client, vaultUri)(_, secretPath)
        )
      }

    override def createSecret[A: Encoder, B: Decoder](
        secretPath: String,
        payload: A
    ): F[VaultSecret[B]] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault
            .generateSecret[F, A, B](client, vaultUri)(_, secretPath, payload)
        )
      }

    override def deleteSecret(secretPath: String): F[Unit] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault.deleteSecret[F](client, vaultUri)(_, secretPath)
        )
      }

    override def renewLease(
        leaseId: String,
        newLeaseDuration: FiniteDuration
    ): F[VaultSecretRenewal] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault.renewLease[F](client, vaultUri)(leaseId, newLeaseDuration, _)
        )
      }

    override def revokeLease(leaseId: String): F[Unit] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(Vault.revokeLease[F](client, vaultUri)(_, leaseId))
      }

    override def generateCertificate(
        secretPath: String,
        payload: CertificateRequest
    ): F[VaultSecret[CertificateData]] =
      retryOnPreconditionFailed {
        tokenRef.get.flatMap(
          Vault.generateCertificate[F](client, vaultUri)(_, secretPath, payload)
        )
      }

    override def mapK[G[_]: Applicative](fg: F ~> G): VaultClient[G] =
      VaultClient.mapK(this, fg)
  }

  private def mapK[F[_], G[_]: Applicative](
      vault: VaultClient[F],
      fg: F ~> G
  ): VaultClient[G] =
    new VaultClient[G] {
      override def readSecret[A: Decoder](
          secretPath: String
      ): G[VaultSecret[A]] =
        fg(vault.readSecret[A](secretPath))

      override def readSecretData[A: Decoder](secretPath: String): G[A] =
        fg(vault.readSecretData[A](secretPath))

      override def listSecrets(secretPath: String): G[VaultKeys] =
        fg(vault.listSecrets(secretPath))

      override def createSecret[A: Encoder, B: Decoder](
          secretPath: String,
          payload: A
      ): G[VaultSecret[B]] =
        fg(vault.createSecret[A, B](secretPath, payload: A))

      override def deleteSecret(secretPath: String): G[Unit] =
        fg(vault.deleteSecret(secretPath))

      override def renewLease(
          leaseId: String,
          newLeaseDuration: FiniteDuration
      ): G[VaultSecretRenewal] =
        fg(vault.renewLease(leaseId, newLeaseDuration))

      override def revokeLease(leaseId: String): G[Unit] =
        fg(vault.revokeLease(leaseId))

      override def generateCertificate(
          secretPath: String,
          payload: CertificateRequest
      ): G[VaultSecret[CertificateData]] =
        fg(vault.generateCertificate(secretPath, payload))

      override protected def applicative: Applicative[G] = Applicative[G]

      override def mapK[H[_]: Applicative](gh: G ~> H): VaultClient[H] =
        VaultClient.mapK(this, gh)
    }

  final class CurrentlyInconsistent(val errors: NonEmptyChain[Throwable])
      extends Throwable {
    override def getMessage: String =
      errors
        .map(_.toString)
        .mkString_(
          "Unable to retrieve eventually consistent value\n",
          "\n",
          "\n"
        )

    override def getCause: Throwable = errors.head
  }
  object CurrentlyInconsistent {

    /** @see
      *   https://developer.hashicorp.com/vault/api-docs#412
      */
    def unapply(e: Throwable): Option[VaultRequestError] = e match {
      case vre @ VaultRequestError(
            _,
            Some(
              UnexpectedStatus(Status.PreconditionFailed, _, _) |
              VaultApiError(Status.PreconditionFailed, _)
            )
          ) =>
        Some(vre)
      case _ => None
    }
  }

  implicit class VaultClientExtensions[F[_]](private val vc: VaultClient[F])
      extends AnyVal {

    /** Similar to [[VaultClient.readSecretData]] but calls
      * [[VaultClient.renewLease]] on a schedule to keep the secret renewed
      * until the resource is closed IF the secret is renewable.
      *
      * If the secret is renewable and becomes un-renewable, each time this
      * happens, a single attempt will be made to re-request the secret.
      *
      * If the secret is not renewable, no attempts to renew will be made, and
      * the behavior will be the same as if [[VaultClient.readSecret]] were
      * called and the result wrapped in a static
      * [[cats.effect.kernel.RefSource]].
      *
      * <h2>CAUTION: Vault secret leases and engine types</h2>
      *
      * While most of the secret related methods in [[VaultClient]] implicitly
      * assume the KV1 secret engine, this method does not.
      *
      * KV1 secret engine leases do not invalidate the secret when they expire,
      * they're cache hints that suggest how long to wait before checking if the
      * value has changed. There's no functional difference between using this
      * method to read a KV1 secret and simply reading the secret once.
      *
      * <h3>HOWEVER: non-KV2 secrets <i>may</i> expire</h3>
      *
      * Dynamic secrets (like database credentials) are a common example, so if
      * a secret becomes invalid after a set period of time, this method may be
      * what is needed.
      *
      * @note
      *   Unless `secretPath` is pointing to a dynamic secret, this provides no
      *   benefit over [[VaultClient.readSecretData]], so it's worth checking to
      *   see if this is actually needed.
      * @note
      *   The `/v1` prefix indicates the API version, not the secret engine
      *   version, check your server config if this distinction matters for your
      *   use case.
      * @see
      *   https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret
      * @param secretLeaseExtension
      *   If provided, determines the maximum delay between token lease
      *   refreshes. If omitted, the TTL provided by the secret will be used.
      */
    def readSecretAndKeep[A: Decoder](
        secretPath: String,
        secretLeaseExtension: Option[FiniteDuration]
    )(implicit
        F: Async[F],
        NEP: NonEmptyParallel[F]
    ): Resource[F, RefSource[F, A]] = {
      val secretLeaseExtensionSeconds =
        secretLeaseExtension.fold(Long.MaxValue)(_.toSeconds)

      // Non-renewable secrets will provide equivalent behavior to `readSecretData`,
      // and it'll eventually just fail, and that is out of our hands.
      def nonRenewableSecretResource(
          vaultSecret: VaultSecret[A]
      ): Resource[F, RefSource[F, A]] =
        Resource
          .pure(new RefSource[F, A] {
            override val get: F[A] = vaultSecret.data.pure[F]
          })

      def renewableSecretResource(
          initialSecret: VaultSecret[A],
          initialLeaseId: String
      ): Resource[F, RefSource[F, A]] =
        Resource
          .make(acquire(initialSecret, initialLeaseId))(release)
          .flatTap { stateRef =>
            stateRef.get
              .flatMap { case (secret, mostRecentLeaseId) =>
                secret.renewal
                  .liftTo[F](NonRenewableSecret(mostRecentLeaseId))
                  .flatMap(renewal =>
                    sleep(renewal) >> renew(secret, renewal, mostRecentLeaseId)
                  )
                  .flatMap(stateRef.set)
              }
              .foreverM
              .background
          }
          .map { stateRef =>
            val stateRefSource: RefSource[F, (VaultSecret[A], String)] =
              stateRef
            stateRefSource.map(_._1.data)
          }

      def readOnce: F[VaultSecret[A]] = vc.readSecret[A](secretPath)

      def acquire(
          initialSecret: VaultSecret[A],
          initialLeaseId: String
      ): F[Ref[F, (VaultSecret[A], String)]] =
        Ref[F].of((initialSecret, initialLeaseId))

      def release(secretRef: Ref[F, (VaultSecret[A], String)]): F[Unit] =
        secretRef.get.flatMap { case (secret, _) =>
          secret.renewal.traverse_ { renewal =>
            vc.revokeLease(renewal.leaseId)
          }
        }

      def sleep(renewal: VaultSecretRenewal): F[Unit] =
        sleepUntilEarliest[F](
          renewal.leaseDuration,
          secretLeaseExtensionSeconds
        )

      def renew(
          oldSecret: VaultSecret[A],
          renewal: VaultSecretRenewal,
          mostRecentLeaseId: String
      ): F[(VaultSecret[A], String)] = {
        val refreshSecret =
          if (renewal.renewable)
            recoverVaultRequestWithRevokeAndRetry(
              vc.renewLease(
                renewal.leaseId,
                secretLeaseExtension.getOrElse(renewal.leaseDuration.seconds)
              ).map(updatedRenewal =>
                oldSecret.copy(renewal = updatedRenewal.some)
              ),
              vc.revokeLease(renewal.leaseId),
              readOnce
            )
          else
            readOnce

        refreshSecret.fproduct { secret =>
          secret.renewal.fold(mostRecentLeaseId)(_.leaseId)
        }
      }

      Resource
        .eval(readOnce)
        .flatMap { vaultSecret =>
          vaultSecret.renewal match {
            case Some(renewal) =>
              renewableSecretResource(vaultSecret, renewal.leaseId)
            case None => nonRenewableSecretResource(vaultSecret)
          }
        }
    }
  }
}
