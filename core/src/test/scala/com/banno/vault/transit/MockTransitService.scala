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

import cats.syntax.flatMap._
import cats.syntax.eq._
import cats.effect.Sync
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import org.http4s.{EntityDecoder, HttpApp, Request, Response}
import org.http4s.util.CaseInsensitiveString

class MockTransitService[F[_]: Sync](
  keyname: String, 
  token: String,
  context: Option[Context],
  encrypted: CipherText,
  plaintext: PlainText
) extends Http4sDsl[F] {

  private implicit val encryptRequestEntityDecoder: EntityDecoder[F, EncryptRequest] = jsonOf
  private implicit val decryptRequestEntityDecoder: EntityDecoder[F, DecryptRequest] = jsonOf

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
        req.as[EncryptRequest].flatMap{ case encreq =>
          if (encreq === EncryptRequest(plaintext,context))
            Ok(s"""
              |{
              | "data": {
              |   "ciphertext": "${encrypted.ciphertext}"
              | }
              |}""".stripMargin)
          else
            Gone()
        }
      case req @ POST -> Root / "v1" / "transit" / "decrypt" / `keyname` => 
        req.as[DecryptRequest].flatMap { case decreq => 
          if (decreq === DecryptRequest(encrypted, context))
            Ok(s"""
              |{
              | "data": {
              |   "plaintext": "${plaintext.plaintext.value}"
              | }
              |}""".stripMargin)
          else Gone()

        }
      case _ => NotFound()
    }}
  }
}