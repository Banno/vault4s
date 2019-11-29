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
import cats.implicits._
import org.specs2.{Spec, ScalaCheck}
import org.specs2.specification.core.SpecStructure
import org.scalacheck.Prop
import io.circe.syntax._ 
import org.scalacheck.Gen

object TransitModelsSpec extends Spec with ScalaCheck {
  import TransitGenerators._

  override def is: SpecStructure = s2"""
      |the Base64 check predicate holds for any ByteVector generated in $isBase64Prop
      |encode an encrypt request in $encodeEncryptRequestProp
      |decode an encrypt response in $decodeEncryptResponseProp
      |encode a  decrypt request in $encodeDecryptRequestProp
      |decode a  decrypt response in $decodeDecryptResponseProp
    """.stripMargin

  val isBase64Prop: Prop = Prop.forAll(byteVector){ bv => 
    Base64.isBase64(bv.toBase64) 
  }

  val encodeEncryptRequestProp: Prop = 
    Prop.forAll(base64, base64){ (plaintext: Base64, context: Base64) =>
      val expected = Json.obj(
        "plaintext" -> Json.fromString(plaintext.value),
        "context"   -> Json.fromString(context.value)
      )
      val input = EncryptRequest(PlainText(plaintext), Some(Context(context)))
      input.asJson === expected
    }

  val decodeEncryptResultProp: Prop = Prop.forAll(cipherText){ (ct: CipherText) =>
    val json = Json.obj("ciphertext" -> Json.fromString(ct.ciphertext))
    EncryptResult.decodeEncryptResult.decodeJson(json) === Right(EncryptResult(ct))
  }

  val decodeEncryptResponseProp: Prop = Prop.forAll(cipherText){ (ct: CipherText) =>
    val json = Json.obj(
      "data" -> Json.obj(
        "ciphertext" -> Json.fromString(ct.ciphertext)
      )
    )
    EncryptResponse.decodeEncryptResponse.decodeJson(json) === Right(EncryptResponse(EncryptResult(ct)))
  }

  val encodeDecryptRequestProp: Prop =
    Prop.forAll(cipherText, base64){ (ct: CipherText, context: Base64) =>
      val expected = Json.obj(
        "ciphertext" -> Json.fromString(ct.ciphertext),
        "context"    -> Json.fromString(context.value)
      )
      DecryptRequest(ct, Some(Context(context))).asJson === expected
    }

  val decodeDecryptResultProp: Prop = Prop.forAll(base64){ (pt: Base64) =>
    val json = Json.obj("plaintext" -> Json.fromString(pt.value))
    DecryptResult.decodeDecryptResult.decodeJson(json) === Right(DecryptResult(PlainText(pt)))
  }

  val decodeDecryptResponseProp: Prop = Prop.forAll(base64){ (plaintext: Base64) =>
    val json = Json.obj(
      "data" -> Json.obj( "plaintext" -> Json.fromString(plaintext.value))
    )
    DecryptResponse.decodeDecryptResponse.decodeJson(json) === Right(DecryptResponse(DecryptResult(PlainText(plaintext))))
  }

  val encodeEncryptBatchRequestProp: Prop = Prop.forAll(genEncryptBatchRequest){ (ebr: EncryptBatchRequest) => 
    ebr.asJson === Json.obj( "batch_input" -> 
      Json.fromValues( ebr.batchInput.map { 
        case EncryptRequest(PlainText(pt), None) => 
          Json.obj(
            "plaintext" -> Json.fromString(pt.value)
          )
        case EncryptRequest(PlainText(pt), Some(Context(ctx))) => 
          Json.obj (
            "plaintext" -> Json.fromString(pt.value),
            "context" -> Json.fromString(ctx.value)
          )
      })
    )
  }

  val encodeEncryptBatchResponseProp: Prop = Prop.forAll(Gen.listOf(cipherText)){ cts =>
    val json = Json.obj("batch_response" -> Json.fromValues(
      cts.map((ct: CipherText) => Json.obj("ciphertext" -> Json.fromString(ct.ciphertext)))
    ))
    EncryptBatchResponse(cts.map((ct: CipherText) => Right(EncryptResult(ct)))).asJson === json
  }

  val decodeDecryptBatchResponseProp: Prop = Prop.forAll(Gen.listOf(base64)){ (plaintexts: List[Base64]) =>
    val json = Json.obj( "batch_response" -> Json.fromValues(
      plaintexts.map( pt => DecryptResult(PlainText(pt)).asJson)
    ))
    val expected = DecryptBatchResponse(plaintexts.map( (pt: Base64) => Right(DecryptResult(PlainText(pt)))))
    DecryptBatchResponse.decodeDecryptBatchResponse.decodeJson(json) === Right(expected)
  }

}
