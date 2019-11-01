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

package com.banno.vault.transit

import cats.Show
import cats.syntax.all._
import cats.effect.Sync
import org.http4s._
import org.http4s.Method.{GET, POST}
import org.http4s.client.Client
import com.banno.vault.models.{VaultRequestError, VaultToken}
import io.circe.Encoder
import org.http4s.circe._

object Transit {

  /** Function to get the details and information of a transit Key, such as the cipher being used,
    *  and whether it supports convergent encryption.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)
      : F[KeyDetails] =
    new TransitClient[F](client, vaultUri, token, key).keyDetails

  /**  Function to encrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt[F[_]: Sync, A: CodecBase64]
    (client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)
    (plainData: A)
      : F[CipherText] =
    new TransitClient[F](client, vaultUri, token, key).encrypt(plainData)

  /**  Function to encrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext[F[_]: Sync, Data: CodecBase64, Context: CodecBase64: Show]
    (client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)
    (data: Data, context: Context)
      : F[CipherText] =
    new TransitClient[F](client, vaultUri, token, key).encryptInContext(data, context)

  /**  Function to decrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt[F[_]: Sync, Data: CodecBase64]
    (client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)
    (cipherText: CipherText)
      : F[Data] =
    new TransitClient[F](client, vaultUri, token, key).decrypt(cipherText)

  /**  Function to decrypt data, given some context information.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decryptInContext[F[_]: Sync, Data: CodecBase64, Context: CodecBase64: Show]
    (client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)
    (cipherText: CipherText, context: Context)
      : F[Data] =
    new TransitClient[F](client, vaultUri, token, key).decryptInContext(cipherText, context)
}

/**
 * A TransitClient represents an authenticated connection to a vault transit service.
 * The way we see to use it is that, in your application you may have a certain type of data
 * that you want to encrypt or decrypt using Vault transit, with a key that is fixed for that data.
 */
final class TransitClient[F[_]](client: Client[F], vaultUri: Uri, token: VaultToken, key: KeyName)(implicit F: Sync[F]) {

  private implicit val encryptResponseEntityDecoder: EntityDecoder[F, EncryptResponse] = jsonOf
  private implicit val decryptResponseEntityDecoder: EntityDecoder[F, DecryptResponse] = jsonOf
  private implicit val keyEntityDecoder: EntityDecoder[F, KeyDetails] = jsonOf

  /* The URIs we use here are those from the transit documentation.
   * the v1 prefix is specified in https://www.vaultproject.io/api/overview
   */
  private val encryptUri: Uri =  vaultUri / "v1" / "transit" / "encrypt" / key.name
  private val decryptUri: Uri =  vaultUri / "v1" / "transit" / "decrypt" / key.name
  private val readKeyUri: Uri =  vaultUri / "v1" / "transit" / "keys"    / key.name

  private val tokenHeaders: Headers = Headers.of(Header("X-Vault-Token", token.clientToken))

  private def doRequest[A](uri: Uri, data: A)(implicit enc: Encoder[A])  =
    Request[F](method = POST, uri = uri, headers = tokenHeaders).withEntity(enc(data))

  /** Function to access the details of a transit Key
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails: F[KeyDetails] = {
    val request = Request[F](method = GET, uri = readKeyUri, headers = tokenHeaders)
    F.handleErrorWith(client.expect[KeyDetails](request)){ e =>
      F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}".some))
    }
  }

  /**  Function to encrypt data, given the name of the secret
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt[A: CodecBase64](plainData: A): F[CipherText] = {
    val encryptReq = EncryptRequest(CodecBase64[A].toBase64(plainData), None)
    val request = doRequest(encryptUri, encryptReq)
    for {
      response <- F.handleErrorWith(client.expect[EncryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}".some))
      }
    } yield response.ciphertext
  }

  /**  Function to encrypt data, adding a context for key derivation.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext[Data: CodecBase64, Context: CodecBase64: Show](data: Data, context: Context): F[CipherText] = {
    val encryptReq = EncryptRequest(
      plaintext = CodecBase64[Data].toBase64(data),
      context   = Some(CodecBase64[Context].toBase64(context))
    )
    val request = doRequest(encryptUri, encryptReq)
    for {
      response <- F.handleErrorWith(client.expect[EncryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, context = $context.show".some))
      }
    } yield response.ciphertext
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
   *
   */
  def decrypt[Data: CodecBase64](cipherText: CipherText): F[Data] = {
    val decryptReq = DecryptRequest(cipherText, None)
    val request = doRequest(decryptUri, decryptReq)
    for {
      response <- F.handleErrorWith(client.expect[DecryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}".some))
      }
      data <- F.fromEither(CodecBase64[Data].fromBase64(response.plaintext))
    } yield data
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
   *
  */
  def decryptInContext[Data: CodecBase64, Context: CodecBase64: Show](cipherText: CipherText, context: Context): F[Data] = {
    val decryptReq = DecryptRequest(cipherText, Some(CodecBase64[Context].toBase64(context)))
    val request = doRequest(decryptUri, decryptReq)
    for {
      response <- F.handleErrorWith(client.expect[DecryptResponse](request)){ e =>
        val showCtx = context.show
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, context = $showCtx".some))
      }
      data <- F.fromEither(CodecBase64[Data].fromBase64(response.plaintext))
    } yield data
  }

}
