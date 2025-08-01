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

import cats.Applicative
import cats.data.NonEmptyList
import cats.effect.Concurrent
import cats.syntax.all.*
import com.banno.vault.impl.Utils.*
import com.banno.vault.models.{VaultRequestError, VaultSecret, VaultToken}
import com.banno.vault.transit.*
import org.http4s.Method.{GET, POST}
import org.http4s.Uri
import org.http4s.Uri.Path
import org.http4s.client.Client
import org.http4s.syntax.literals.*

private[vault] object TransitApi {

  def keyAsPath(key: KeyName): Path =
    Uri.Path.unsafeFromString(key.name.dropWhile(_ === '/'))

  /* The URIs we use here are those from the transit documentation.
   * the v1 prefix is specified in https://www.vaultproject.io/api/overview
   */
  private[this] def readKeyUri(vaultUri: Uri, key: Path): Uri =
    vaultUri.withPath(path"/v1/transit/keys/" |+| key)

  private[this] def encryptKeyUri(vaultUri: Uri, key: Path): Uri =
    vaultUri.withPath(path"/v1/transit/encrypt/" |+| key)

  private[this] def decryptKeyUri(vaultUri: Uri, key: Path): Uri =
    vaultUri.withPath(path"/v1/transit/decrypt/" |+| key)

  /** https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      key: Path
  ): F[KeyDetails] = {
    val request = authedRequest[F](GET, readKeyUri(vaultUri, key), token)

    client.expect[KeyDetails](request).adaptErr { e =>
      VaultRequestError(
        request,
        e.some,
        s"keyName=${key.renderString}, operation=GetKey".some
      )
    }
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      key: Path,
      plaintext: PlainText,
      context: Option[Context]
  ): F[CipherText] = {
    val request =
      authedRequest[F](POST, encryptKeyUri(vaultUri, key), token)
        .withEntity(EncryptRequest(plaintext, context))

    for {
      response <- client.expect[EncryptResponse](request).adaptErr { e =>
        VaultRequestError(
          request,
          e.some,
          s"keyName=${key.renderString}, operation=EncryptOne, context = ${context.fold("none")(_.context.value)}".some
        )
      }
    } yield response.data.ciphertext
  }

  /**   - https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    *   - https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptBatch[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      key: Path,
      payload: EncryptBatchRequest,
      opNameForErrors: String
  ): F[NonEmptyList[Either[TransitError, CipherText]]] = {
    val request = authedRequest[F](POST, encryptKeyUri(vaultUri, key), token)
      .withEntity(payload)

    for {
      results <-
        client
          .expect[VaultSecret[EncryptBatchResponse]](request)
          .map(_.data.batchResults)
          .adaptErr { e =>
            VaultRequestError(
              request,
              e.some,
              s"keyName=${key.renderString}, operation=$opNameForErrors".some
            )
          }
      _ <-
        Applicative[F].unlessA(results.exists(_.isRight)) {
          VaultRequestError(
            request,
            None,
            s"keyName=${key.renderString}, operation=$opNameForErrors, all requests failed".some
          ).raiseError[F, Unit]
        }
    } yield results.map(_.map(_.ciphertext))
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      key: Path,
      cipherText: CipherText,
      contextOpt: Option[Context]
  ): F[PlainText] = {
    val decryptReq = DecryptRequest(cipherText, contextOpt)
    val request = authedRequest[F](POST, decryptKeyUri(vaultUri, key), token)
      .withEntity(decryptReq)

    for {
      response <- client.expect[DecryptResponse](request).adaptErr { e =>
        val showCtx = contextOpt.fold("none")(_.context.value)
        VaultRequestError(
          request,
          e.some,
          s"keyName=${key.renderString}, operation=DecryptOne, context = $showCtx".some
        )
      }
    } yield response.data.plaintext
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptBatch[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: VaultToken,
      key: Path,
      payload: DecryptBatchRequest,
      opNameForErrors: String
  ): F[NonEmptyList[Either[TransitError, PlainText]]] = {
    val request = authedRequest[F](POST, decryptKeyUri(vaultUri, key), token)
      .withEntity(payload)

    for {
      results <-
        client
          .expect[DecryptBatchResponse](request)
          .map(_.data.batchResults)
          .adaptErr { e =>
            VaultRequestError(
              request,
              e.some,
              s"keyName=${key.renderString}, operation=$opNameForErrors".some
            )
          }
      _ <-
        Applicative[F].unlessA(results.exists(_.isRight)) {
          VaultRequestError(
            request,
            None,
            s"keyName=${key.renderString}, operation=$opNameForErrors, all requests failed".some
          ).raiseError[F, Unit]
        }
    } yield results.map(_.map(_.plaintext))
  }
}
