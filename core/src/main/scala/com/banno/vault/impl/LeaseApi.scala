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

package com.banno.vault.impl

import cats.*
import cats.effect.*
import cats.syntax.all.*
import com.banno.vault.Vault
import com.banno.vault.impl.Utils.*
import com.banno.vault.models.*
import io.circe.*
import io.circe.syntax.*
import org.http4s.*
import org.http4s.Method.{POST, PUT}
import org.http4s.circe.*
import org.http4s.client.*
import org.http4s.implicits.*

import scala.concurrent.duration.*

private[vault] object LeaseApi {

  /** https://www.vaultproject.io/api/system/leases.html#renew-lease
    */
  def renewLease[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      leaseId: String,
      newLeaseDuration: FiniteDuration,
      token: VaultToken
  ): F[VaultSecretRenewal] = {
    val request =
      authedRequest[F](
        PUT,
        vaultUri.withPath(path"/v1/sys/leases/renew"),
        token
      ).withEntity(
        Json.obj(
          "lease_id" := leaseId,
          "increment" := newLeaseDuration.toSeconds
        )
      )

    decodeResponseOrFail[F, VaultSecretRenewal](
      request,
      client.run(request),
      _.hcursor,
      s"tokenLength=${token.clientToken.length}".some,
      df =>
        InvalidMessageBodyFailure(
          "Could not decode vault lease renew response",
          df.some
        )
    )
  }

  /** https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token-self
    */
  def renewSelfToken[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      newLeaseDuration: FiniteDuration
  ): F[VaultToken] =
    if (!token.renewable)
      Vault.NonRenewableToken(token.clientToken).raiseError[F, VaultToken]
    else {
      val request = authedRequest[F](
        POST,
        vaultUri / "v1" / "auth" / "token" / "renew-self",
        token
      ).withEntity(
        Json.obj("increment" := s"${newLeaseDuration.toSeconds}s")
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
  def revokeSelfToken[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken
  ): F[Unit] = {
    val request = authedRequest[F](
      POST,
      vaultUri / "v1" / "auth" / "token" / "revoke-self",
      token
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
  def revokeLease[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      leaseId: String
  ): F[Unit] = {
    val request = authedRequest[F](
      PUT,
      vaultUri.withPath(path"/v1/sys/leases/revoke"),
      token
    ).withEntity(
      Json.obj("lease_id" := leaseId)
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
}
