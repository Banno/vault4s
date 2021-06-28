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

import cats.{ApplicativeError, Eq}
import cats.kernel.instances.string._
import cats.instances.either._
import io.circe.{Encoder, Decoder, Json}
import scodec.bits.{ByteVector, BitVector}

/** A String wrapper class, to ensure that the string inside is a valid
  *  Base64 string, as those used in Vault to represent plaintext and context. 
  */
final class Base64 private[Base64] (val value: String) extends AnyVal {
  override def toString = s"Base64($value)"
}

object Base64 {

  implicit val eqBase64: Eq[Base64] = Eq.by[Base64, String](_.value)

  implicit final val decodeBase64: Decoder[Base64] =
    Decoder[String].emap(Base64.fromString[Either[String, *]])
  implicit final val encodeBase64: Encoder[Base64] =
    Encoder.instance(bv => Json.fromString(bv.value))


  /** A cost-free predicate to check if a String is a valid encoding outcome as described in
    * https://tools.ietf.org/html/rfc4648#section-4. 
    * 
    * Meaning: its length is a multiple of 4, and all its characters are letters, digits, '+' or '/'. 
    * Except at the end, where either: a) the last two characters can both be padding `=``; 
    *  or b) only the last character is padding; or c) no character is padding.   */
  private[transit] def isBase64(str: String): Boolean =
    (str.length & 3) == 0 && {
      (str.length - str.count(isBase64)) match {
        case 0 => true
        case 1 => isPadding(str.charAt(str.length -1))
        case 2 => isPadding(str.charAt(str.length -1)) && isPadding(str.charAt(str.length - 2))
        case _ => false
      }
    }

  private def isBase64(char: Char): Boolean = char.isLetterOrDigit || char == '/' || char == '+'
  private def isPadding(char: Char): Boolean = char == '='

  def fromStringOpt(str: String): Option[Base64] =
    if (isBase64(str)) Some(new Base64(str)) else None
  
  def fromString[F[_]](str: String)(implicit F: ApplicativeError[F, String]): F[Base64] =
    if (isBase64(str)) F.pure(new Base64(str))
    else F.raiseError(s"""The string "$str" is not a valid Base-64 encoded literal""")

  def fromByteVector(bv: ByteVector): Base64 = new Base64(bv.toBase64)

  def fromBitVector(bv: BitVector): Base64 = new Base64(bv.toBase64)

  private[transit] def unsafeFrom(str: String): Base64 = new Base64(str)
}
