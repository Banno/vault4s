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

import io.circe.Json
import cats.data.NonEmptyList
import cats.implicits._
import munit.ScalaCheckSuite
import org.scalacheck.Prop
import io.circe.syntax._

class TransitModelsSpec extends ScalaCheckSuite {
  import TransitGenerators._

  property("The Base64 check predicate holds for any ByteVector generated in") {
    Prop.forAll(byteVector) { bv =>
      Base64.isBase64(bv.toBase64)
    }
  }

  property("encode an encrypt request in") {
    Prop.forAll(base64, base64) { (plaintext: Base64, context: Base64) =>
      val expected = Json.obj(
        "plaintext" -> Json.fromString(plaintext.value),
        "context" -> Json.fromString(context.value)
      )
      val input = EncryptRequest(PlainText(plaintext), Some(Context(context)))
      input.asJson === expected
    }
  }

  property("decode an encrypt response in") {
    Prop.forAll(cipherText) { (ct: CipherText) =>
      val json = Json.obj("ciphertext" -> Json.fromString(ct.ciphertext))
      EncryptResult.decodeEncryptResult.decodeJson(json) === Right(
        EncryptResult(ct)
      )
    }
  }

  property("ecode an encrypt response in $decodeEncryptResponseProp") {
    Prop.forAll(cipherText) { (ct: CipherText) =>
      val json = Json.obj(
        "data" -> Json.obj(
          "ciphertext" -> Json.fromString(ct.ciphertext)
        )
      )
      EncryptResponse.decodeEncryptResponse.decodeJson(json) === Right(
        EncryptResponse(EncryptResult(ct))
      )
    }
  }

  property("encode an decrypt request in") {
    Prop.forAll(cipherText, base64) { (ct: CipherText, context: Base64) =>
      val expected = Json.obj(
        "ciphertext" -> Json.fromString(ct.ciphertext),
        "context" -> Json.fromString(context.value)
      )
      DecryptRequest(ct, Some(Context(context))).asJson === expected
    }
  }

  property("decode a decrypt result in") {
    Prop.forAll(base64) { (pt: Base64) =>
      val json = Json.obj("plaintext" -> Json.fromString(pt.value))
      DecryptResult.decodeDecryptResult.decodeJson(json) === Right(
        DecryptResult(PlainText(pt))
      )
    }
  }

  property("decode a decrypt response in") {
    Prop.forAll(base64) { (plaintext: Base64) =>
      val json = Json.obj(
        "data" -> Json.obj("plaintext" -> Json.fromString(plaintext.value))
      )
      DecryptResponse.decodeDecryptResponse.decodeJson(json) === Right(
        DecryptResponse(DecryptResult(PlainText(plaintext)))
      )
    }
  }

  property("encode EncryptBatchRequest in") {
    Prop.forAll(genEncryptBatchRequest) { (ebr: EncryptBatchRequest) =>
      ebr.asJson === Json.obj(
        "batch_input" ->
          Json.fromValues(ebr.batchInput.map {
            case EncryptRequest(PlainText(pt), None) =>
              Json.obj(
                "plaintext" -> Json.fromString(pt.value)
              )
            case EncryptRequest(PlainText(pt), Some(Context(ctx))) =>
              Json.obj(
                "plaintext" -> Json.fromString(pt.value),
                "context" -> Json.fromString(ctx.value)
              )
          }.toList)
      )
    }
  }

  property("encode EncryptBatchResponse in") {
    Prop.forAll(nelGen(cipherText)) { cts =>
      val json = Json.obj(
        "batch_results" -> Json.fromValues(
          cts
            .map((ct: CipherText) =>
              Json.obj("ciphertext" -> Json.fromString(ct.ciphertext))
            )
            .toList
        )
      )
      EncryptBatchResponse(
        cts.map((ct: CipherText) => Right(EncryptResult(ct)))
      ).asJson === json
    }
  }

  property("decode DecryptBatchResponse in") {
    Prop.forAll(nelGen(base64)) { (plaintexts: NonEmptyList[Base64]) =>
      val json = Json.obj(
        "batch_results" -> Json.fromValues(
          plaintexts.map(pt => DecryptResult(PlainText(pt)).asJson).toList
        )
      )
      val expected = DecryptBatchResults(
        plaintexts.map((pt: Base64) => Right(DecryptResult(PlainText(pt))))
      )
      DecryptBatchResults.decodeDecryptBatchResults.decodeJson(json) === Right(
        expected
      )
    }
  }

}
