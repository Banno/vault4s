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

import cats.data.NonEmptyList
import cats.effect.Concurrent
import cats.implicits.*
import com.banno.vault.impl.TransitApi
import com.banno.vault.models.VaultToken
import org.http4s.*
import org.http4s.client.Client

object Transit {

  /** Function to get the details and information of a transit Key, such as the
    * cipher being used, and whether it supports convergent encryption.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  ): F[KeyDetails] =
    TransitApi.keyDetails(client, vaultUri, token, TransitApi.keyAsPath(key))

  /** Function to encrypt data.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(plaintext: PlainText): F[CipherText] =
    TransitApi.encrypt(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      plaintext,
      none
    )

  /** Function to encrypt data.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(plaintext: PlainText, context: Context): F[CipherText] =
    TransitApi.encrypt(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      plaintext,
      context.some
    )

  /** Function to encrypt data.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptBatch[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(
      plaintexts: NonEmptyList[PlainText]
  ): F[NonEmptyList[TransitError.Or[CipherText]]] = {
    val payload = EncryptBatchRequest(plaintexts.map(EncryptRequest(_, None)))
    TransitApi.encryptBatch(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      payload,
      "EncryptBatch without context"
    )
  }

  /** Function to decrypt data.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(cipherText: CipherText): F[PlainText] =
    TransitApi.decrypt(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      cipherText,
      none
    )

  /** Function to decrypt data, given some context information.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decryptInContext[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(cipherText: CipherText, context: Context): F[PlainText] =
    TransitApi.decrypt(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      cipherText,
      context.some
    )

  /** Function to decrypt data, given some context information.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    *
    * Returns a list of the results, where each entry in the list is the result
    * of attempting to decrypt the ciphertext that was located at the same
    * position in the input. The result is either an error, if something went
    * wrong with this particular CipherText, or the PlainText.
    */
  def decryptBatch[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(
      cipherTexts: NonEmptyList[CipherText]
  ): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(cipherTexts.map(DecryptRequest(_, None)))
    TransitApi.decryptBatch(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      payload,
      "DecryptBatch without context"
    )
  }

  /** Function to decrypt a batch of data, where each ciphertext is accompanied
    * by its context information.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    *
    * Returns a list of the results, where each entry in the list is the result
    * of attempting to decrypt the ciphertext that was located at the same
    * position in the input. The result is either an error, if something went
    * wrong with this particular input pair of CipherText and Context, or with
    * the PlainText.
    */
  def decryptBatchInContext[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String,
      key: KeyName
  )(
      inputs: NonEmptyList[(CipherText, Context)]
  ): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(inputs.map { case (cipht, ctx) =>
      DecryptRequest(cipht, Some(ctx))
    })
    TransitApi.decryptBatch(
      client,
      vaultUri,
      token,
      TransitApi.keyAsPath(key),
      payload,
      "DecryptBatch with context"
    )
  }
}

/** A TransitClient represents an authenticated connection to a vault transit
  * service. The way we see to use it is that, in your application you may have
  * a certain type of data that you want to encrypt or decrypt using Vault
  * transit, with a key that is fixed for that data.
  */
final class TransitClient[F[_]](
    client: Client[F],
    vaultUri: Uri,
    vaultTokenF: F[VaultToken],
    keyPath: Uri.Path
)(implicit F: Concurrent[F]) {
  def this(client: Client[F], vaultUri: Uri, token: String, keyName: KeyName)(
      implicit F: Concurrent[F]
  ) = {
    this(
      client,
      vaultUri,
      VaultToken(token, Long.MaxValue, false).pure[F],
      TransitApi.keyAsPath(keyName)
    )
  }

  private def clientTokenF: F[String] = vaultTokenF.map(_.clientToken)

  /** Function to access the details of a transit Key
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails: F[KeyDetails] =
    clientTokenF.flatMap(TransitApi.keyDetails[F](client, vaultUri, _, keyPath))

  /** Function to encrypt data, given the name of the secret
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt(plaintext: PlainText): F[CipherText] =
    clientTokenF.flatMap(
      TransitApi.encrypt[F](client, vaultUri, _, keyPath, plaintext, none)
    )

  /** Function to encrypt data, adding a context for key derivation.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext(
      plaintext: PlainText,
      context: Context
  ): F[CipherText] =
    clientTokenF.flatMap(
      TransitApi.encrypt(
        client,
        vaultUri,
        _,
        keyPath,
        plaintext,
        context.some
      )
    )

  /** Function to encrypt a batch of data, without any context.
    *
    * When encrypting a batch of data, transit may work ok for some inputs, but
    * fail for others. That is why the result is a list where each element is
    * either a failed message or a CipherText
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptBatch(
      plaintexts: NonEmptyList[PlainText]
  ): F[NonEmptyList[TransitError.Or[CipherText]]] = {
    val payload = EncryptBatchRequest(plaintexts.map(EncryptRequest(_, None)))
    clientTokenF.flatMap(
      TransitApi.encryptBatch(
        client,
        vaultUri,
        _,
        keyPath,
        payload,
        "EncryptBatch without context"
      )
    )
  }

  /** Function to encrypt a batch of context-plaintext pairs in a single trip.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptInContextBatch(
      inputs: NonEmptyList[(PlainText, Context)]
  ): F[NonEmptyList[TransitError.Or[CipherText]]] = {
    val payload = EncryptBatchRequest(inputs.map { case (pt, ctx) =>
      EncryptRequest(pt, Some(ctx))
    })
    clientTokenF.flatMap(
      TransitApi.encryptBatch(
        client,
        vaultUri,
        _,
        keyPath,
        payload,
        "EncryptBatch with context"
      )
    )
  }

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt(cipherText: CipherText): F[PlainText] =
    clientTokenF.flatMap(
      TransitApi.decrypt(client, vaultUri, _, keyPath, cipherText, none)
    )

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decryptInContext(
      cipherText: CipherText,
      context: Context
  ): F[PlainText] =
    clientTokenF.flatMap(
      TransitApi.decrypt(
        client,
        vaultUri,
        _,
        keyPath,
        cipherText,
        context.some
      )
    )

  /** Decrypts a batch of input ciphertexts using a single round-trip to the
    * Vault server. Returns a list where each entry is the attempted result of
    * decrypting the ciphertext at the same position. That result may be either
    * a Transit error or the plaintext, if it failed or succeeded for that
    * ciphertext.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptBatch(
      inputs: NonEmptyList[CipherText]
  ): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(inputs.map(DecryptRequest(_, None)))
    clientTokenF.flatMap(
      TransitApi.decryptBatch(
        client,
        vaultUri,
        _,
        keyPath,
        payload,
        "DecryptBatch without context"
      )
    )
  }

  /** Decrypts a batch of input pairs (ciphertexts and contexts) using a single
    * round-trip to the Vault server. Returns a list where each entry is the
    * attempted result of decrypting the input at the same position. That result
    * may be either a Transit error or the plaintext.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptInContextBatch(
      inputs: NonEmptyList[(CipherText, Context)]
  ): F[NonEmptyList[TransitError.Or[PlainText]]] = {
    val payload = DecryptBatchRequest(inputs.map { case (cipht, ctx) =>
      DecryptRequest(cipht, Some(ctx))
    })
    clientTokenF.flatMap(
      TransitApi.decryptBatch(
        client,
        vaultUri,
        _,
        keyPath,
        payload,
        "DecryptBatch with context"
      )
    )
  }
}
