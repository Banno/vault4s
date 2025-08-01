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
import cats.data.NonEmptyList
import cats.effect.kernel.Concurrent
import cats.kernel.instances.all.*
import cats.syntax.eq.*
import com.banno.vault.models.VaultSecret
import io.circe.{Decoder, Encoder, HCursor, Json}
import org.http4s.circe.{jsonEncoderOf, jsonOf}
import org.http4s.{EntityDecoder, EntityEncoder}

import java.time.Instant

final case class KeyName(name: String)
final case class KeyDetails(
    name: String,
    isConvergent: Boolean,
    isDerived: Boolean,
    versions: Map[Int, Instant],
    cipher: String
)

object KeyDetails {

  implicit final val encodeKeyDetails: Encoder[KeyDetails] =
    Encoder.instance { (kd: KeyDetails) =>
      Json.obj(
        "data" -> Json.obj(
          "name" -> Json.fromString(kd.name),
          "type" -> Json.fromString(kd.cipher),
          "convergent_encryption" -> Json.fromBoolean(kd.isConvergent),
          "derived" -> Json.fromBoolean(kd.isDerived),
          "keys" -> Json.fromFields(
            kd.versions.map { case (num, inst) =>
              num.toString -> Json.fromLong(inst.getEpochSecond)
            }
          )
        )
      )
    }

  implicit final val decodeKeyDetails: Decoder[KeyDetails] = {
    implicit val decodeInstantSecond: Decoder[Instant] =
      Decoder.decodeLong.emap { numsec =>
        if (numsec <= Instant.MAX.getEpochSecond)
          Right(Instant.ofEpochSecond(numsec))
        else
          Left(
            s"value $numsec of UNIX epoch seconds is over Java maximum Instant"
          )
      }
    Decoder.instance[KeyDetails] { c =>
      Decoder.resultInstance.map5(
        c.downField("data").downField("name").as[String],
        c.downField("data")
          .downField("convergent_encryption")
          .as[Option[Boolean]]
          .map(_.getOrElse(false)),
        c.downField("data").downField("derived").as[Boolean],
        c.downField("data").downField("keys").as[Map[Int, Instant]],
        c.downField("data").downField("type").as[String]
      )(KeyDetails.apply(_, _, _, _, _))
    }
  }

  implicit def entityDecoder[F[_]: Concurrent]: EntityDecoder[F, KeyDetails] =
    jsonOf
}

/** A tagged-like newtype used to indicate that a Base64 value is a plaintext we
  * want to encrypt.
  */
final case class PlainText(plaintext: Base64)
object PlainText {
  implicit val eqPlainText: Eq[PlainText] =
    Eq.by[PlainText, Base64](_.plaintext)
  private[vault] implicit val encodePlainText: Encoder[PlainText] =
    Base64.encodeBase64.contramap(_.plaintext)
  private[vault] implicit val decodePlainText: Decoder[PlainText] =
    Base64.decodeBase64.map(PlainText.apply)
}

/** A tagged-like newtype used to indicate that a Base64 value is the
  * user-supplied context used in key derivation. "Key derivation allows the
  * same key to be used for multiple purposes by deriving a new key based on a
  * user-supplied context value
  *
  * https://www.vaultproject.io/docs/secrets/transit/index.html#transit-secrets-engine
  */
final case class Context(context: Base64)
object Context {
  implicit val eqContext: Eq[Context] =
    Eq.by[Context, Base64](_.context)
  private[vault] implicit val encodeContext: Encoder[Context] =
    Base64.encodeBase64.contramap(_.context)
  private[vault] implicit val decodeContext: Decoder[Context] =
    Base64.decodeBase64.map(Context.apply)
}

/** In the Vault Transit, cipher-texts are Base64 strings preceded by the
  * `"vault:v1:"` prefix text. We our special wrapper class to represent Base64
  * Strings.
  */
final case class CipherText(ciphertext: String) extends AnyVal
object CipherText {
  private[vault] implicit val encodeCipherText: Encoder[CipherText] =
    Encoder.encodeString.contramap(_.ciphertext)
  private[vault] implicit val decodeCipherText: Decoder[CipherText] =
    Decoder.decodeString.map(CipherText.apply)
  implicit val eqCipherText: Eq[CipherText] =
    Eq.by[CipherText, String](_.ciphertext)
}

final case class EncryptRequest(plaintext: PlainText, context: Option[Context])
object EncryptRequest {
  implicit val eqEncryptRequest: Eq[EncryptRequest] =
    Eq.instance { (x: EncryptRequest, y: EncryptRequest) =>
      x.context === y.context && x.plaintext === y.plaintext
    }
  implicit val encodeEncryptRequest: Encoder[EncryptRequest] =
    Encoder.forProduct2("plaintext", "context")(er =>
      (er.plaintext, er.context)
    )
  implicit val decodeEncryptRequest: Decoder[EncryptRequest] =
    Decoder.forProduct2("plaintext", "context")(
      (pt: PlainText, ct: Option[Context]) => EncryptRequest(pt, ct)
    )

  implicit def entityEncoder[F[_]: Concurrent]
      : EntityEncoder[F, EncryptRequest] = jsonEncoderOf
}

private[vault] final case class EncryptResult(ciphertext: CipherText)
private[vault] object EncryptResult {
  implicit val eqEncryptResult: Eq[EncryptResult] = Eq.by(_.ciphertext)

  implicit val encodeEncryptResult: Encoder[EncryptResult] =
    Encoder.instance { (er: EncryptResult) =>
      Json.obj(
        "ciphertext" -> Encoder[CipherText].apply(er.ciphertext)
      )
    }

  implicit val decodeEncryptResult: Decoder[EncryptResult] =
    Decoder.forProduct1("ciphertext")((ct: CipherText) =>
      EncryptResult.apply(ct)
    )
}

private[vault] case class EncryptResponse(data: EncryptResult)
private[vault] object EncryptResponse {
  implicit val eqEncryptResponse: Eq[EncryptResponse] =
    Eq.by[EncryptResponse, EncryptResult](_.data)
  implicit val encodeEncryptResponse: Encoder[EncryptResponse] =
    Encoder.forProduct1("data")(_.data)
  implicit val decodeEncryptResponse: Decoder[EncryptResponse] =
    Decoder.forProduct1("data")((d: EncryptResult) => EncryptResponse(d))

  implicit def entityDecoder[F[_]: Concurrent]
      : EntityDecoder[F, EncryptResponse] = jsonOf
}

private[vault] final case class EncryptBatchRequest(
    batchInput: NonEmptyList[EncryptRequest]
)
private[vault] object EncryptBatchRequest {
  implicit val eqEncryptBatchRequest: Eq[EncryptBatchRequest] =
    Eq.by[EncryptBatchRequest, NonEmptyList[EncryptRequest]](_.batchInput)
  implicit val encodeEncryptBatchRequest: Encoder[EncryptBatchRequest] =
    Encoder.forProduct1("batch_input")(_.batchInput)
  implicit val decodeEncryptBatchRequest: Decoder[EncryptBatchRequest] =
    Decoder.forProduct1("batch_input")((bi: NonEmptyList[EncryptRequest]) =>
      EncryptBatchRequest(bi)
    )

  implicit def entityEncoder[F[_]: Concurrent]
      : EntityEncoder[F, EncryptBatchRequest] = jsonEncoderOf
}

private[vault] final case class EncryptBatchResponse(
    batchResults: NonEmptyList[TransitError.Or[EncryptResult]]
)
private[vault] object EncryptBatchResponse {
  implicit val eqEncryptBatchResponse: Eq[EncryptBatchResponse] =
    Eq.by(_.batchResults)
  implicit val encodeEncryptBatchResponse: Encoder[EncryptBatchResponse] =
    Encoder.forProduct1("batch_results")(_.batchResults)
  implicit val decodeEncryptBatchResponse: Decoder[EncryptBatchResponse] =
    Decoder.forProduct1("batch_results")(
      (br: NonEmptyList[TransitError.Or[EncryptResult]]) =>
        EncryptBatchResponse(br)
    )

  implicit def decoder[F[_]: Concurrent]
      : EntityDecoder[F, VaultSecret[EncryptBatchResponse]] = jsonOf
}

private[vault] final case class DecryptRequest(
    ciphertext: CipherText,
    context: Option[Context]
)
private[vault] object DecryptRequest {
  implicit val eqDecryptRequest: Eq[DecryptRequest] =
    Eq.instance { (x: DecryptRequest, y: DecryptRequest) =>
      x.context === y.context && x.ciphertext === y.ciphertext
    }

  implicit val encodeDecryptRequest: Encoder[DecryptRequest] =
    Encoder.forProduct2("ciphertext", "context")(dr =>
      (dr.ciphertext, dr.context)
    )

  implicit val decodeDecryptRequest: Decoder[DecryptRequest] =
    Decoder.forProduct2("ciphertext", "context")(
      (cr: CipherText, ct: Option[Context]) => DecryptRequest(cr, ct)
    )

  implicit def entityEncoder[F[_]: Concurrent]
      : EntityEncoder[F, DecryptRequest] = jsonEncoderOf
}

private[vault] final case class DecryptResult(plaintext: PlainText)
private[vault] object DecryptResult {
  implicit val eqDecryptResponse: Eq[DecryptResult] =
    Eq.by[DecryptResult, PlainText](_.plaintext)

  implicit val encodeDecryptResult: Encoder[DecryptResult] =
    Encoder.forProduct1("plaintext")(_.plaintext)

  /* We need custom decoder because sometimes, field `plaintext` may be empty in the response.
   * See https://github.com/hashicorp/vault/issues/6140  */
  implicit val decodeDecryptResult: Decoder[DecryptResult] =
    new Decoder[DecryptResult] {
      def apply(c: HCursor) =
        c.downField("plaintext").as[Option[PlainText]].map { optPt =>
          DecryptResult(optPt.getOrElse(PlainText(Base64.empty)))
        }
    }
}

private[vault] final case class DecryptResponse(data: DecryptResult)
private[vault] object DecryptResponse {
  implicit val eqDecryptResponse: Eq[DecryptResponse] =
    Eq.by[DecryptResponse, DecryptResult](_.data)

  implicit val encodeDecryptResponse: Encoder[DecryptResponse] =
    Encoder.forProduct1("data")(_.data)
  implicit val decodeDecryptResponse: Decoder[DecryptResponse] =
    Decoder.forProduct1("data")((d: DecryptResult) => DecryptResponse(d))

  implicit def entityDecoder[F[_]: Concurrent]
      : EntityDecoder[F, DecryptResponse] = jsonOf
}

final case class TransitError(error: String)
private[vault] object TransitError {
  type Or[A] = Either[TransitError, A]

  implicit val eqError: Eq[TransitError] = Eq.by(_.error)

  implicit val encodeError: Encoder[TransitError] =
    Encoder.forProduct1("error")(_.error)

  implicit val decodeError: Decoder[TransitError] =
    Decoder.forProduct1("error")((e: String) => TransitError(e))

  implicit def encodeOr[A](implicit encodeA: Encoder[A]): Encoder[Or[A]] =
    Encoder.instance {
      case Left(err) => encodeError(err)
      case Right(a)  => encodeA(a)
    }

  implicit def decodeOr[A](implicit decodeA: Decoder[A]): Decoder[Or[A]] =
    decodeError either decodeA

}

private[vault] final case class DecryptBatchRequest(
    batchInput: NonEmptyList[DecryptRequest]
)
private[vault] object DecryptBatchRequest {
  implicit val eqDecryptBatchRequest: Eq[DecryptBatchRequest] =
    Eq.by[DecryptBatchRequest, NonEmptyList[DecryptRequest]](_.batchInput)
  implicit val encodeDecryptBatchRequest: Encoder[DecryptBatchRequest] =
    Encoder.forProduct1("batch_input")(_.batchInput)
  implicit val decodeDecryptBatchRequest: Decoder[DecryptBatchRequest] =
    Decoder.forProduct1("batch_input")((bi: NonEmptyList[DecryptRequest]) =>
      DecryptBatchRequest(bi)
    )

  implicit def entityEncoder[F[_]: Concurrent]
      : EntityEncoder[F, DecryptBatchRequest] = jsonEncoderOf
}
private[vault] final case class DecryptBatchResponse(
    data: DecryptBatchResults
)
private[vault] object DecryptBatchResponse {
  implicit val eqDecryptBatchResponse: Eq[DecryptBatchResponse] =
    Eq.by[DecryptBatchResponse, DecryptBatchResults](_.data)

  implicit val encodeDecryptBatchResponse: Encoder[DecryptBatchResponse] =
    Encoder.forProduct1("data")(_.data)
  implicit val decodeDecryptBatchResponse: Decoder[DecryptBatchResponse] =
    Decoder.forProduct1("data")(apply)

  implicit def decoder[F[_]: Concurrent]
      : EntityDecoder[F, DecryptBatchResponse] = jsonOf
}

private[vault] final case class DecryptBatchResults(
    batchResults: NonEmptyList[TransitError.Or[DecryptResult]]
)
private[vault] object DecryptBatchResults {
  implicit val eqDecryptBatchResults: Eq[DecryptBatchResults] =
    Eq.by[DecryptBatchResults, NonEmptyList[TransitError.Or[DecryptResult]]](
      _.batchResults
    )
  implicit val encodeDecryptBatchResults: Encoder[DecryptBatchResults] =
    Encoder.forProduct1("batch_results")(_.batchResults)
  implicit val decodeDecryptBatchResults: Decoder[DecryptBatchResults] =
    Decoder.forProduct1("batch_results")(apply)
}
