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

import cats.syntax.eq._
import cats.instances.option._
import cats.effect.Sync
import io.circe.Json
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import org.http4s.{DecodeFailure, EntityDecoder, HttpApp, Request, Response}
import org.http4s.util.CaseInsensitiveString
import cats.data.EitherT

final class MockTransitService[F[_]: Sync](
  keyname: String, 
  token: String,
  encryptCase: EncryptCase,
  batchCases: List[EncryptCase]
) extends Http4sDsl[F] {

  private implicit val encryptRequestEntityDecoder: EntityDecoder[F, EncryptRequest] = jsonOf
  private implicit val decryptRequestEntityDecoder: EntityDecoder[F, DecryptRequest] = jsonOf
  private implicit val encryptBatchRequestEntityDecoder: EntityDecoder[F, EncryptBatchRequest] = jsonOf
  private implicit val decryptBatchRequestEntityDecoder: EntityDecoder[F, DecryptBatchRequest] = jsonOf

  private def findVaultToken(req: Request[F]): Option[String] =
    req.headers.find(_.name == CaseInsensitiveString("X-Vault-Token")).map(_.value)

  private def checkVaultToken(req: Request[F])(resp: F[Response[F]]): F[Response[F]] =
    findVaultToken(req) match {
      case None => BadRequest(""" {"errors": [ "missing client token"] }""")
      case Some(`token`) => resp
      case Some(_) => Forbidden(""" {"errors": [ "permission denied"] }""")
    }

  val routes: HttpApp[F] = HttpApp.apply[F] { req =>
    checkVaultToken(req){ req match {
      case req @ POST -> Root / "v1" / "transit" / "encrypt" / `keyname` =>
        ( encryptOne(req) orElse encryptBatch(req)) getOrElseF NotFound()
      case req @ POST -> Root / "v1" / "transit" / "decrypt" / `keyname` => 
        (decryptOne(req) orElse decryptBatch(req)) getOrElseF NotFound()
      case _ => NotFound()
    }}
  }


  private def encryptResult(ct: CipherText): Json = 
    Json.obj("ciphertext" -> Json.fromString(ct.ciphertext) )

  private def decryptResult(pt: PlainText): Json = 
    Json.obj("plaintext" -> Json.fromString(pt.plaintext.value) )

  private def error(str: String): Json = 
    Json.obj("error" -> Json.fromString(str))

  private def encryptOne(req: Request[F]): EitherT[F, DecodeFailure, Response[F]] = 
    req.attemptAs[EncryptRequest].semiflatMap { case encReq =>
      if (encryptCase.matches(encReq))
        Ok( Json.obj("data" -> encryptResult(encryptCase.ciphertext)))
      else
        Gone()
    }
  
  private def decryptOne(req: Request[F]): EitherT[F, DecodeFailure, Response[F]] = 
    req.attemptAs[DecryptRequest].semiflatMap { case decreq => 
      if (encryptCase.matches(decreq))
        Ok( Json.obj("data" -> decryptResult(encryptCase.plaintext)))
      else Gone()
    }

  private def decryptBatch(req: Request[F]): EitherT[F, DecodeFailure, Response[F]] = 
    req.attemptAs[DecryptBatchRequest].semiflatMap { case DecryptBatchRequest(inputs) => 
      val results: List[Json] = inputs.map { case decreq =>
        batchCases.find(_.matches(decreq)) match {
          case None => error("Not known for this context or ciphertext")
          case Some(bc) => decryptResult(bc.plaintext)
        }
      }
      Ok(Json.obj("batch_results" -> Json.fromValues(results)))
    }

  private def encryptBatch(req: Request[F]): EitherT[F, DecodeFailure, Response[F]] = 
    req.attemptAs[EncryptBatchRequest].semiflatMap { case EncryptBatchRequest(inputs) =>
      val results: List[Json] = inputs.map { case encReq => 
        batchCases.find(_.matches(encReq)) match {
          case None => error("Not known for this context or plaintext")
          case Some(bc) => encryptResult(bc.ciphertext)
        }
      }
      Ok(Json.obj("batch_results" -> Json.fromValues(results)))
    }
}

final case class EncryptCase(
  plaintext: PlainText,
  context: Option[Context],
  ciphertext: CipherText
){
  def matches(req: EncryptRequest): Boolean = 
    req.plaintext === plaintext && req.context === context
  def matches(req: DecryptRequest): Boolean = 
    req.ciphertext === ciphertext && req.context === context
}
