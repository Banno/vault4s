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

import cats.syntax.all._
import cats.data.NonEmptyList
import cats.effect.Sync
import org.http4s._
import org.http4s.Method.{GET, POST}
import org.http4s.client.Client
import com.banno.vault.models.VaultRequestError
import io.circe.Encoder
import org.http4s.circe._

object Transit {

  /** Function to get the details and information of a transit Key, such as the cipher being used,
    *  and whether it supports convergent encryption.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
      : F[KeyDetails] =
    new TransitClient[F](client, vaultUri, token, key).keyDetails

  /**  Function to encrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (plaintext: PlainText)
      : F[CipherText] =
    new TransitClient[F](client, vaultUri, token, key).encrypt(plaintext)

  /**  Function to encrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (plaintext: PlainText, context: Context)
      : F[CipherText] =
    new TransitClient[F](client, vaultUri, token, key).encryptInContext(plaintext, context)

  /**  Function to encrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    *  https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptBatch[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (plaintexts: NonEmptyList[PlainText])
      : F[NonEmptyList[TransitError.Or[CipherText]]] =
    new TransitClient[F](client, vaultUri, token, key).encryptBatch(plaintexts)

  /**  Function to decrypt data.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (cipherText: CipherText)
      : F[PlainText] =
    new TransitClient[F](client, vaultUri, token, key).decrypt(cipherText)

  /**  Function to decrypt data, given some context information.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decryptInContext[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (cipherText: CipherText, context: Context)
      : F[PlainText] =
    new TransitClient[F](client, vaultUri, token, key).decryptInContext(cipherText, context)

  /**  Function to decrypt data, given some context information.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    *
    *  Returns a list of the results, where each entry in the list is the result of attempting to decrypt the ciphertext
    *  that was located at the same position in the input. The result is either an error, if something went wrong
    *  with this particular CipherText, or the PlainText.
    */
  def decryptBatch[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (cipherTexts: NonEmptyList[CipherText])
      : F[NonEmptyList[TransitError.Or[PlainText]]] =
    new TransitClient[F](client, vaultUri, token, key).decryptBatch(cipherTexts)

  /**  Function to decrypt a batch of data, where each ciphertext is accompanied by its context information.
      *
      *  https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
      *
      *  Returns a list of the results, where each entry in the list is the result of attempting to decrypt the ciphertext
      *  that was located at the same position in the input. The result is either an error, if something went wrong
      *  with this particular input pair of CipherText and Context, or with the PlainText.
      */
  def decryptBatchInContext[F[_]: Sync]
    (client: Client[F], vaultUri: Uri, token: String, key: KeyName)
    (inputs: NonEmptyList[(CipherText, Context)])
      : F[NonEmptyList[TransitError.Or[PlainText]]] =
    new TransitClient[F](client, vaultUri, token, key).decryptInContextBatch(inputs)

}

/**
 * A TransitClient represents an authenticated connection to a vault transit service.
 * The way we see to use it is that, in your application you may have a certain type of data
 * that you want to encrypt or decrypt using Vault transit, with a key that is fixed for that data.
 */
final class TransitClient[F[_]](client: Client[F], vaultUri: Uri, token: String, key: KeyName)(implicit F: Sync[F]) {

  private implicit val encryptResponseEntityDecoder: EntityDecoder[F, EncryptResponse] = jsonOf
  private implicit val decryptResponseEntityDecoder: EntityDecoder[F, DecryptResponse] = jsonOf
  private implicit val keyEntityDecoder: EntityDecoder[F, KeyDetails] = jsonOf
  private implicit val ebred: EntityDecoder[F, EncryptBatchResponse] = jsonOf
  private implicit val dbred: EntityDecoder[F, DecryptBatchResponse] = jsonOf[F, DecryptBatchResponse]

  /* The URIs we use here are those from the transit documentation.
   * the v1 prefix is specified in https://www.vaultproject.io/api/overview
   */
  private val keyAsPath: String = key.name.dropWhile(_ === '/')

  private val encryptUri: Uri = vaultUri.withPath(s"/v1/transit/encrypt/${keyAsPath}")
  private val decryptUri: Uri = vaultUri.withPath(s"/v1/transit/decrypt/${keyAsPath}")
  private val readKeyUri: Uri = vaultUri.withPath(s"/v1/transit/keys/${keyAsPath}")

  private val tokenHeaders: Headers = Headers.of(Header("X-Vault-Token", token))

  private def postOf[A](uri: Uri, data: A)(implicit enc: Encoder[A])  =
    Request[F](method = POST, uri = uri, headers = tokenHeaders).withEntity(enc(data))

  /** Function to access the details of a transit Key
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  val keyDetails: F[KeyDetails] = {
    val request = Request[F](method = GET, uri = readKeyUri, headers = tokenHeaders)
    F.handleErrorWith(client.expect[KeyDetails](request)){ e =>
      F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=GetKey".some))
    }
  }

  /**  Function to encrypt data, given the name of the secret
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt(plaintext: PlainText): F[CipherText] = {
    val request = postOf(encryptUri, EncryptRequest(plaintext, None))
    for {
      response <- F.handleErrorWith(client.expect[EncryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=EncryptOne, no context".some))
      }
    } yield response.data.ciphertext
  }

  /**  Function to encrypt data, adding a context for key derivation.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext(plaintext: PlainText, context: Context): F[CipherText] = {
    val request = postOf(encryptUri, EncryptRequest(plaintext, Some(context)))
    for {
      response <- F.handleErrorWith(client.expect[EncryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=EncryptOne, context = ${context.context.value}".some))
      }
    } yield response.data.ciphertext
  }

  /** Function to encrypt a batch of data, without any context.
    *
    * When encrypting a batch of data, transit may work ok for some inputs, but fail for others.
    * That is why the result is a list where each element is either a failed message or a CipherText
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptBatch(plaintexts: NonEmptyList[PlainText]): F[NonEmptyList[TransitError.Or[CipherText]]] = {
    val payload = EncryptBatchRequest(plaintexts.map(EncryptRequest(_, None)))
    encryptBatchAux(payload, "EncryptBatch without context")
  }

  /** Function to encrypt a batch of context-plaintext pairs in a single trip.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptInContextBatch(inputs: NonEmptyList[(PlainText, Context)]): F[NonEmptyList[TransitError.Or[CipherText]]] = {
      val payload = EncryptBatchRequest(inputs.map { case (pt, ctx) => EncryptRequest(pt, Some(ctx)) })
      encryptBatchAux(payload, "EncryptBatch with context")
    }

  private def encryptBatchAux(payload: EncryptBatchRequest, op: String): F[NonEmptyList[TransitError.Or[CipherText]]] = {
    val request = postOf(encryptUri, payload)
    for {
      results <- F.handleErrorWith(client.expect[EncryptBatchResponse](request).map(_.batchResults)) {
        case e => F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=$op".some))
      }
      _ <- if (results.exists(_.isRight)) F.unit else F.raiseError {
        VaultRequestError(request, None, s"keyName=${key.name}, operation=$op, all requests failed".some)
      }
    } yield results.map(_.map(_.ciphertext))
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
   *
   */
  def decrypt(cipherText: CipherText): F[PlainText] = {
    val request = postOf(decryptUri, DecryptRequest(cipherText, None))
    for {
      response <- F.handleErrorWith(client.expect[DecryptResponse](request)){ e =>
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=DecryptOne, no context".some))
      }
    } yield response.data.plaintext
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
   *
  */
  def decryptInContext(cipherText: CipherText, context: Context): F[PlainText] = {
    val decryptReq = DecryptRequest(cipherText, Some(context))
    val request = postOf(decryptUri, decryptReq)
    for {
      response <- F.handleErrorWith(client.expect[DecryptResponse](request)){ e =>
        val showCtx = context.context.value
        F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=DecryptOne, context = $showCtx".some))
      }
    } yield response.data.plaintext
  }

  /** Decrypts a batch of input ciphertexts using a single round-trip to the Vault server.
    * Returns a list where each entry is the attempted result of decrypting the ciphertext at the same position.
    * That result may be either a Transit error or the plaintext, if it failed or succeeded for that ciphertext.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptBatch(inputs: NonEmptyList[CipherText]): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(inputs.map((cipht: CipherText) => DecryptRequest(cipht, None)))
    decryptBatchAux(payload, "DecryptBatch without context")
  }

  /** Decrypts a batch of input pairs (ciphertexts and contexts) using a single round-trip to the Vault server.
    * Returns a list where each entry is the attempted result of decrypting the input at the same position.
    * That result may be either a Transit error or the plaintext.
    *
    *  https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptInContextBatch(inputs: NonEmptyList[(CipherText, Context)]): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(inputs.map { case (cipht, ctx) => DecryptRequest(cipht, Some(ctx)) } )
    decryptBatchAux(payload, "DecryptBatch with context")
  }

  private def decryptBatchAux(payload: DecryptBatchRequest, op: String): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val request = postOf(decryptUri, payload)
    for {
      results <- F.handleErrorWith(client.expect[DecryptBatchResponse](request).map(_.batchResults)){
        case e => F.raiseError(VaultRequestError(request, e.some, s"keyName=${key.name}, operation=$op".some))
      }
      _ <- if (results.exists(_.isRight)) F.unit else F.raiseError {
        VaultRequestError(request, None, s"keyName=${key.name}, operation=$op, all requests failed".some)
      }
    } yield results.map(_.map(_.plaintext))
  }

}
