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

  val genChar: Gen[Char] = Gen.choose[Char](Char.MinValue, Char.MaxValue)
  val genString: Gen[String] = Gen.listOf(genChar).map(_.mkString)

  // copied from scodec-bits repository.
  def standardByteVectors(maxSize: Int): Gen[ByteVector] = for {
    size <- Gen.choose(0, maxSize)
    bytes <- Gen.listOfN(size, Gen.choose(0, 255))
  } yield ByteVector(bytes: _*)

  val byteVector: Gen[ByteVector] = Gen.choose(1, 1000).flatMap(standardByteVectors)

  val base64: Gen[Base64] = byteVector.map(Base64.fromByteVector)

  // we generate examples like we have seen so far: a base64-encoded literal, prefixed by `vault:v1:` 
  val cipherText: Gen[CipherText] = base64.map( x => CipherText(s"vault:v1:${x.value}"))

}