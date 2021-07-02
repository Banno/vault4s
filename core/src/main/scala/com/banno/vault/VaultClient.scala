package com.banno.vault

import cats.effect.kernel.{Concurrent, Ref, Resource, Temporal}
import cats.effect.syntax.all._
import com.banno.vault.models._
import io.circe.Decoder
import org.http4s.Uri
import org.http4s.client.Client
import scala.concurrent.duration.FiniteDuration

trait VaultClient[F[_]] {
  def readSecret[A: Decoder](secretPath: String): F[VaultSecret[A]]
}

object VaultClient {
  def apply[F[_]](implicit ev: VaultClient[F]): VaultClient[F] = ev

  def login[F[_]](client: Client[F], vaultUri: Uri, roleId: String, tokenLeaseExtension: FiniteDuration)
    (implicit F: Temporal[F]): Resource[F, VaultClient[F]] = {

    def startRenewalStream(ref: Ref[F, VaultToken], token: VaultToken) =
      Vault.tokenStream(client, vaultUri)(token, tokenLeaseExtension)
        .evalMap(newToken => ref.set(newToken))
        .compile
        .drain
        .start

    for {
      token <- Resource.make(Vault.login[F](client, vaultUri)(roleId))(Vault.revokeSelfToken(client, vaultUri))
      tokenRef <- Resource.eval(Ref.of(token))
      _ <- Resource.make(startRenewalStream(tokenRef, token))(_.cancel)
    } yield impl(client, vaultUri, token)
  }

  private def impl[F[_]: Concurrent](client: Client[F], vaultUri: Uri, tokenRef: Ref[F, VaultToken]): VaultClient[F] =
    new VaultClient[F] {
      def readSecret[A: Decoder](secretPath: String): F[VaultSecret[A]] =
        tokenRef.get.flatMap(token =>
          Vault.readSecret(client, vaultUri)(token.clientToken, secretPath))
    }
}
