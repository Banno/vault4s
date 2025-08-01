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
import cats.~>
import com.banno.vault.transit.TransitError.Or

/** A TransitClient represents an authenticated connection to a vault transit
  * service. The way we see to use it is that, in your application you may have
  * a certain type of data that you want to encrypt or decrypt using Vault
  * transit, with a key that is fixed for that data.
  */
trait VaultTransitClient[F[_]] {

  /** Function to access the details of a transit Key
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#read-key
    */
  def keyDetails: F[KeyDetails]

  /** Function to encrypt data, given the name of the secret
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encrypt(plaintext: PlainText): F[CipherText]

  /** Function to encrypt data, adding a context for key derivation.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
    */
  def encryptInContext(plaintext: PlainText, context: Context): F[CipherText]

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
  ): F[NonEmptyList[TransitError.Or[CipherText]]]

  /** Function to encrypt a batch of context-plaintext pairs in a single trip.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input
    */
  def encryptInContextBatch(
      inputs: NonEmptyList[(PlainText, Context)]
  ): F[NonEmptyList[TransitError.Or[CipherText]]]

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decrypt(cipherText: CipherText): F[PlainText]

  /** https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
    */
  def decryptInContext(cipherText: CipherText, context: Context): F[PlainText]

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
  ): F[NonEmptyList[TransitError.Or[PlainText]]]

  /** Decrypts a batch of input pairs (ciphertexts and contexts) using a single
    * round-trip to the Vault server. Returns a list where each entry is the
    * attempted result of decrypting the input at the same position. That result
    * may be either a Transit error or the plaintext.
    *
    * https://www.vaultproject.io/api/secret/transit/index.html#batch_input-2
    */
  def decryptInContextBatch(
      inputs: NonEmptyList[(CipherText, Context)]
  ): F[NonEmptyList[TransitError.Or[PlainText]]]

  def mapK[G[_]](fg: F ~> G): VaultTransitClient[G] =
    VaultTransitClient.mapK(this, fg)
}
object VaultTransitClient {
  private def mapK[F[_], G[_]](
      tc: VaultTransitClient[F],
      fg: F ~> G
  ): VaultTransitClient[G] =
    new VaultTransitClient[G] {
      override def keyDetails: G[KeyDetails] =
        fg(tc.keyDetails)

      override def encrypt(plaintext: PlainText): G[CipherText] =
        fg(tc.encrypt(plaintext))

      override def encryptInContext(
          plaintext: PlainText,
          context: Context
      ): G[CipherText] =
        fg(tc.encryptInContext(plaintext, context))

      override def encryptBatch(
          plaintexts: NonEmptyList[PlainText]
      ): G[NonEmptyList[Or[CipherText]]] =
        fg(tc.encryptBatch(plaintexts))

      override def encryptInContextBatch(
          inputs: NonEmptyList[(PlainText, Context)]
      ): G[NonEmptyList[Or[CipherText]]] =
        fg(tc.encryptInContextBatch(inputs))

      override def decrypt(cipherText: CipherText): G[PlainText] =
        fg(tc.decrypt(cipherText))

      override def decryptInContext(
          cipherText: CipherText,
          context: Context
      ): G[PlainText] =
        fg(tc.decryptInContext(cipherText, context))

      override def decryptBatch(
          inputs: NonEmptyList[CipherText]
      ): G[NonEmptyList[Or[PlainText]]] =
        fg(tc.decryptBatch(inputs))

      override def decryptInContextBatch(
          inputs: NonEmptyList[(CipherText, Context)]
      ): G[NonEmptyList[Or[PlainText]]] =
        fg(tc.decryptInContextBatch(inputs))

      override def mapK[H[_]](gh: G ~> H): VaultTransitClient[H] =
        VaultTransitClient.mapK(this, gh)
    }
}
