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
import com.banno.vault.impl.DecodeUtils.*
import com.banno.vault.models.*
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.*
import org.http4s.implicits.*
import org.typelevel.ci.CIString

import scala.concurrent.duration.*

private[vault] object LeaseApi {

  /** https://www.vaultproject.io/api/system/leases.html#renew-lease
    */
  def renewLease[F[_]](client: Client[F], vaultUri: Uri)(
      leaseId: String,
      newLeaseDuration: FiniteDuration,
      token: String
  )(implicit F: Concurrent[F]): F[VaultSecretRenewal] = {
    val request = Request[F](
      method = Method.PUT,
      uri = vaultUri.withPath(path"/v1/sys/leases/renew"),
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
      Vault.NonRenewableToken(token.clientToken).raiseError[F, VaultToken]
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
      uri = vaultUri.withPath(path"/v1/sys/leases/revoke"),
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
}
