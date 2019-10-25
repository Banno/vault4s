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

object TransitCodersSpec extends Spec with ScalaCheck {
  import TransitGenerators._

  override def is: SpecStructure = s2"""
      |encode a cipher text with the given prefix in $encodeCiphertext
      |decode a cipher text with the given prefix in $decodeRoundTrip
      |encode an encrypt request in $encodeEncryptRequestProp
      |decode an encrypt response in $decodeEncryptResponseProp
      |encode a  decrypt request in $encodeDecryptRequestProp
      |decode a  decrypt response in $decodeDecryptResponseProp
    """.stripMargin

  val encodeCiphertext: Prop = Prop.forAll(base64){ (bv: Base64) => 
    val actual = CipherText(bv).asJson 
    val expected = Json.fromString(s"vault:v1:${bv.value}")
    (actual === expected) :| s"actual is $actual, expected is $expected" 
  }

  val decodeRoundTrip: Prop = Prop.forAll(base64){ (bv: Base64) =>
    import CipherText._
    decodeCipherText.decodeJson(encodeCipherText(CipherText(bv))) === Right(CipherText(bv))
  }

  val encodeEncryptRequestProp: Prop = 
    Prop.forAll(base64, base64){ (plaintext: Base64, context: Base64) =>
      val expected = Json.obj(
        "plaintext" -> Json.fromString(plaintext.value),
        "context"   -> Json.fromString(context.value)
      )
      val input = EncryptRequest(plaintext, Some(context))
      input.asJson === expected
    }

  val decodeEncryptResponseProp: Prop = Prop.forAll(base64){ (ct: Base64) =>
    val json = Json.obj(
      "data" -> Json.obj(
        "ciphertext" -> Json.fromString(s"vault:v1:${ct.value}")
      )
    )
    EncryptResponse.decodeEncryptResponse.decodeJson(json) === Right(EncryptResponse(CipherText(ct)))
  }

  val encodeDecryptRequestProp: Prop =
    Prop.forAll(base64, base64){ (ciphertext: Base64, context: Base64) =>
      val expected = Json.obj(
        "ciphertext" -> CipherText(ciphertext).asJson,
        "context" -> Json.fromString(context.value)
      )
      val input = DecryptRequest(CipherText(ciphertext), Some(context))
      input.asJson === expected
    }

  val decodeDecryptResponseProp: Prop = Prop.forAll(base64){ (plaintext: Base64) =>
    val json = Json.obj(
      "data" -> Json.obj( "plaintext" -> Json.fromString(plaintext.value))
    )
    DecryptResponse.decodeDecryptResponse.decodeJson(json) === Right(DecryptResponse(plaintext))
  }

}
