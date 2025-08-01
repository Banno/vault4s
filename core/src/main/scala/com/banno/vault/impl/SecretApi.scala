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
import com.banno.vault.impl.DecodeUtils.*
import com.banno.vault.models.*
import io.circe.*
import io.circe.syntax.*
import org.http4s.*
import org.http4s.Uri.Path
import org.http4s.circe.*
import org.http4s.client.*
import org.http4s.implicits.*
import org.typelevel.ci.CIString

/** Helper methods for working with Vault
  */
private[vault] object SecretApi {

  /** https://www.vaultproject.io/api/secret/kv/index.html#read-secret
    */
  def readSecret[F[_], A](client: Client[F], vaultUri: Uri)(
      token: String,
      secretPath: Path
  )(implicit F: Concurrent[F], D: Decoder[A]): F[VaultSecret[A]] = {
    val request = Request[F](
      method = Method.GET,
      uri = vaultUri.withPath(path"/v1".concat(secretPath)),
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
      secretPath: Path
  )(implicit F: Concurrent[F]): F[VaultKeys] = {
    val request = Request[F](
      method = Method.GET,
      uri = vaultUri
        .withPath(path"/v1".concat(secretPath))
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
      secretPath: Path
  )(implicit F: Concurrent[F]): F[Unit] = {
    val request = Request[F](
      method = Method.DELETE,
      uri = vaultUri.withPath(path"/v1".concat(secretPath)),
      headers = Headers(Header.Raw(CIString("X-Vault-Token"), token))
    )

    client
      .run(request)
      .use(expectSuccessOrFail(request, _, s"tokenLength=${token.length}".some))
  }

  /**   - https://www.vaultproject.io/api/secret/pki/index.html#generate-certificate
    *   - https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#create-update-secret
    */
  def generateSecret[F[_], A: Encoder, B: Decoder](
      client: Client[F],
      vaultUri: Uri
  )(token: String, secretPath: Path, payload: A)(implicit
      F: Concurrent[F]
  ): F[VaultSecret[B]] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri.withPath(path"/v1".concat(secretPath)),
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
}
