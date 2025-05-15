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
import cats.effect.{Async, Ref}
import cats.syntax.all.*
import cats.{Applicative, NonEmptyParallel, ~>}
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
  */
trait VaultClient[F[_]] {

  /** @note
    *   Despite being a prefix common to all secrets, `secret/` does need to
    *   appear in `secretPath`. `/v1/`, however, does not need to be included.
    *
    * If a secret resides at `/v1/secret/foo/bar/baz`, then `secretPath` should
    * be `secret/foo/bar/baz`
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

    def sleep(token: VaultToken): F[Unit] = {
      val waitInterval: Long =
        Math.min(
          token.leaseDuration,
          vaultConfig.tokenLeaseExtension.toSeconds
        ) * 9 / 10

      Async[F].sleep(waitInterval.seconds)
    }

    def renew(token: VaultToken): F[VaultToken] =
      if (token.renewable)
        renewWithRetry(token, client, vaultConfig, consistencyConfig)
          .recoverWith { case vre: VaultRequestError =>
            (revoke(token).attempt, login.attempt).parFlatMapN {
              case (_, Right(token)) => token.pure[F]
              case (Right(_), Left(loginError)) =>
                if (!(vre eq loginError)) {
                  vre.addSuppressed(loginError)
                }
                loginError.raiseError[F, VaultToken]
              case (Left(revokeError), Left(loginError)) =>
                if (!(vre eq revokeError)) {
                  vre.addSuppressed(revokeError)
                }
                if (!(vre eq loginError)) {
                  vre.addSuppressed(loginError)
                }
                loginError.raiseError[F, VaultToken]
            }
          }
      else
        login

    Resource
      .make(login.flatMap(Ref[F].of(_)))(_.get.flatMap(revoke))
      .flatTap { vaultTokenRef =>
        Async[F].background {
          vaultTokenRef.get
            .flatMap(token => sleep(token) >> renew(token))
            .flatMap(vaultTokenRef.set)
            .foreverM
        }
      }
      .map(ref => (ref: RefSource[F, VaultToken]).map(_.clientToken))
      .map(new Default[F](client, vaultConfig.vaultUri, _, consistencyConfig))
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
    )
      .recoverWith {
        case VaultRequestError(
              _,
              Some(UnexpectedStatus(Status.Forbidden, _, _))
            ) =>
          // This means the token has already expired or been revoked, so we can ignore this
          Async[F].unit
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
            Some(UnexpectedStatus(Status.PreconditionFailed, _, _))
          ) =>
        Some(vre)
      case _ => None
    }
  }
}
