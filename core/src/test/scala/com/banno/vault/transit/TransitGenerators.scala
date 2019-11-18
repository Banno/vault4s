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

import com.banno.vault.VaultArbitraries
import scodec.bits.ByteVector
import org.scalacheck.Gen

object TransitGenerators extends VaultArbitraries {

  // copied from scodec-bits repository.
  def standardByteVectors(maxSize: Int): Gen[ByteVector] = for {
    size <- Gen.choose(0, maxSize)
    bytes <- Gen.listOfN(size, Gen.choose(0, 255))
  } yield ByteVector(bytes: _*)

  val byteVector: Gen[ByteVector] = Gen.choose(1, 1000).flatMap(standardByteVectors)

  val base64: Gen[Base64] = byteVector.map(Base64.fromByteVector)

  // we generate examples like we have seen so far: a base64-encoded literal, prefixed by `vault:v1:`
  val cipherText: Gen[CipherText] = base64.map( x => CipherText(s"vault:v1:${x.value}"))
  val plaintext: Gen[PlainText] = base64.map( (p: Base64) => PlainText(p))
  val context: Gen[Context] = base64.map( (p: Base64) => Context(p))

  val transitError: Gen[TransitError] = Gen.alphaNumStr.map( (s: String) => TransitError(s))

  val genEncryptRequest: Gen[EncryptRequest] =
    for { pt <- plaintext ; ctx <- context } yield EncryptRequest(pt, Some(ctx))

  val encryptResult: Gen[EncryptResult] = 
    cipherText.map((p: CipherText) => EncryptResult(p))

  val genEncryptBatchRequest: Gen[EncryptBatchRequest] =
    Gen.listOf(genEncryptRequest).map(ps => EncryptBatchRequest(ps))
 
  val genAllRightEncryptBatchResponse: Gen[EncryptBatchResponse] =
    Gen.listOf(right[TransitError, EncryptResult](encryptResult))
      .map( (rps: List[TransitError.Or[EncryptResult]]) => EncryptBatchResponse(rps))

  val genEncryptBatchResponse: Gen[EncryptBatchResponse] =
    Gen.listOf(errorOr(encryptResult))
      .map((rps: List[TransitError.Or[EncryptResult]]) => EncryptBatchResponse(rps))

  def some[A](genA: Gen[A]): Gen[Option[A]] = genA.map( (a:A) => Some(a) )
  def right[A, B](genB: Gen[B]): Gen[Either[A, B]] = genB.map(b => Right(b))

  def errorOr[A](genA: Gen[A]): Gen[TransitError.Or[A]] = either(transitError, genA)

  def either[T, U](gt: Gen[T], gu: Gen[U]): Gen[Either[T, U]] =
    Gen.oneOf(gt.map(Left(_)), gu.map(Right(_)))

}