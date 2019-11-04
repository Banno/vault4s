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

import cats.Eq
import cats.kernel.instances.option._
import cats.kernel.instances.string._
import cats.syntax.eq._
import io.circe.{Decoder, Encoder, Json}
import java.time.Instant

/** A Cipher or "type" of Key, which indicates the algorithm being used for encrypting or decrypting. */
sealed abstract class Cipher private (val name: String)
object Cipher {
  /* Source: https://www.vaultproject.io/api/secret/transit/index.html#type */
  case object Aes256Gcm96 extends Cipher("aes256-gcm96")
  case object ChaCha20Poly1305 extends Cipher("chacha20-poly1305")
  case object ED25519 extends Cipher("ed25519")
  case object EcDsaP256 extends Cipher("ecdsa-p256")
  case object Rsa2048 extends Cipher("rsa-2048")
  case object Rsa4096 extends Cipher("rsa-4096")

  val values: IndexedSeq[Cipher] = Vector(Aes256Gcm96, ChaCha20Poly1305, ED25519, EcDsaP256, Rsa2048, Rsa4096) 

  def findEither(name: String): Either[String, Cipher] = 
    values.find( _.name == name).toRight(s"$name is not a known name of a vault type key")
}

final case class KeyName(name: String)
final case class KeyDetails(
  name: String,
  isConvergent: Boolean,
  isDerived: Boolean,
  versions: Map[Int, Instant],
  cipher: Cipher
)

object KeyDetails {

  implicit final val encodeKeyDetails: Encoder[KeyDetails] =
    (kd: KeyDetails) => Json.obj(
      "data" -> Json.obj(
        "name"                  -> Json.fromString(kd.name),
        "type"                  -> Json.fromString(kd.cipher.name),
        "convergent_encryption" -> Json.fromBoolean(kd.isConvergent),
        "derived"               -> Json.fromBoolean(kd.isDerived),
        "keys"                  -> Json.fromFields(
          kd.versions.map { case (num, inst) =>
            num.toString -> Json.fromLong(inst.getEpochSecond)
          }
        )
      )
    )

    implicit final val decodeCipher: Decoder[Cipher] = 
      Decoder.decodeString.emap(Cipher.findEither)

    implicit final val decodeKeyDetails: Decoder[KeyDetails] = {
      implicit val decodeInstantSecond: Decoder[Instant] = 
        Decoder.decodeLong.emap { numsec =>
          if (numsec <= Instant.MAX.getEpochSecond) 
            Right(Instant.ofEpochSecond(numsec))
          else Left(s"value $numsec of UNIX epoch seconds is over Java maximum Instant")
        }
      Decoder.instance[KeyDetails] { c => 
        Decoder.resultInstance.map5(
          c.downField("data").downField("name").as[String],
          c.downField("data").downField("convergent_encryption").as[Boolean],
          c.downField("data").downField("derived").as[Boolean],
          c.downField("data").downField("keys").as[Map[Int, Instant]],
          c.downField("data").downField("type").as[Cipher],
        ){ KeyDetails.apply(_,_,_,_,_)}
      }
    }
      
}

/** A tagged-like newtype used to indicate that a Base64 value is a plaintext we want to encrypt. 
  */
final case class PlainText(val plaintext: Base64)
object PlainText {
  implicit val eqPlainText: Eq[PlainText] =
    Eq.by[PlainText, Base64](_.plaintext)
  private[transit] implicit val encodePlainText: Encoder[PlainText] =
    Base64.encodeBase64.contramap(_.plaintext)
  private[transit] implicit val decodePlainText: Decoder[PlainText] =
    Base64.decodeBase64.map(PlainText.apply)
}

/** A tagged-like newtype used to indicate that a Base64 value is the user-supplied context used in key derivation. 
  * "Key derivation allows the same key to be used for multiple purposes 
  * by deriving a new key based on a user-supplied context value
  *
  * https://www.vaultproject.io/docs/secrets/transit/index.html#transit-secrets-engine
  */
final case class Context(val context: Base64)
object Context {
  implicit val eqContext: Eq[Context] =
    Eq.by[Context, Base64](_.context)
  private[transit] implicit val encodeContext: Encoder[Context] =
    Base64.encodeBase64.contramap(_.context)
  private[transit] implicit val decodeContext: Decoder[Context] =
    Base64.decodeBase64.map(Context.apply)
}

/** In the Vault Transit, cipher-texts are Base64 strings preceded by the `"vault:v1:"` prefix text.
  * We our special wrapper class to represent Base64 Strings.  
  */
final case class CipherText(ciphertext: String) extends AnyVal
object CipherText {
  private[transit] implicit val encodeCipherText: Encoder[CipherText] = 
    Encoder.encodeString.contramap(_.ciphertext)
  private[transit] implicit val decodeCipherText: Decoder[CipherText] = 
    Decoder.decodeString.map(CipherText.apply)
  implicit val eqCipherText: Eq[CipherText] = 
    Eq.by[CipherText, String](_.ciphertext)
}

private[transit] final case class EncryptRequest(plaintext: PlainText, context: Option[Context])
private[transit] object EncryptRequest {
  implicit val eqEncryptRequest: Eq[EncryptRequest] = { (x: EncryptRequest, y: EncryptRequest) =>
    x.context === y.context && x.plaintext === y.plaintext
  }
  implicit val encodeEncryptRequest: Encoder[EncryptRequest] =
    Encoder.forProduct2("plaintext", "context")(er => (er.plaintext, er.context))
  implicit val decodeEncryptRequest: Decoder[EncryptRequest] =
    Decoder.forProduct2("plaintext", "context")(EncryptRequest.apply(_,_))
}

private[transit] final case class EncryptResponse(ciphertext: CipherText)
private[transit] object EncryptResponse {
  implicit val eqEncryptResponse: Eq[EncryptResponse] = Eq.by(_.ciphertext)

  implicit val encodeEncryptResponse: Encoder[EncryptResponse] =
    (er: EncryptResponse) => Json.obj( "data" -> 
      Json.obj("ciphertext" -> Encoder[CipherText].apply(er.ciphertext))
    )

    implicit val decodeEncryptResponse: Decoder[EncryptResponse] =
    _.downField("data").get[CipherText]("ciphertext").map(EncryptResponse.apply)
}

private[transit] final case class DecryptRequest(ciphertext: CipherText, context: Option[Context])
private[transit] object DecryptRequest {
  implicit val eqDecryptResponse: Eq[DecryptRequest] = { 
    (x: DecryptRequest, y: DecryptRequest) => x.context === y.context && x.ciphertext === y.ciphertext
  }

  implicit val encodeDecryptRequest: Encoder[DecryptRequest] =
    Encoder.forProduct2("ciphertext", "context")(dr => (dr.ciphertext, dr.context))

  implicit val decodeDecryptRequest: Decoder[DecryptRequest] =
    Decoder.forProduct2("ciphertext", "context")(DecryptRequest.apply(_,_))
}

private[transit] final case class DecryptResponse(plaintext: PlainText)
private[transit] object DecryptResponse {
  implicit val eqDecryptResponse: Eq[DecryptResponse] =
    Eq.by[DecryptResponse, PlainText](_.plaintext)

  implicit val encodeDecryptResponse: Encoder[DecryptResponse] =
    (dr: DecryptResponse) => Json.obj(
      "data" -> Json.obj("plaintext" -> Encoder[PlainText].apply(dr.plaintext))
    )
  implicit val decodeDecryptResponse: Decoder[DecryptResponse] =
    _.downField("data").get[PlainText]("plaintext").map(DecryptResponse.apply(_))
}
