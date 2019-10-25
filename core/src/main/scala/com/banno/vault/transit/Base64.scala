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
import cats.kernel.instances.string._
import java.nio.charset.{StandardCharsets/*, CharacterCodingException*/}
import java.util.{Base64 => J64}
import scala.util.{Failure, Success, Try}
import scala.util.control.NoStackTrace
import io.circe.{Encoder, Decoder, Json}
import scodec.bits.ByteVector

/** A String wrapper class, to ensure that the string inside is a valid
  *  Base64 string, as those used in Vault to represent plaintext and context. 
  */
class Base64 private[Base64] (val value: String)

object Base64 {

  implicit val eqBase64: Eq[Base64] = Eq.by[Base64, String](_.value)

  implicit final val decodeBase64: Decoder[Base64] =
    Decoder[String].emap(Base64.fromStringEither)
  implicit final val encodeBase64: Encoder[Base64] =
    Encoder.instance(bv => Json.fromString(bv.value))


  /** A cost-free predicate to check if a String is a valid encoding outcome as described in
    * https://tools.ietf.org/html/rfc4648#section-4. 
    * 
    * Meaning: its length is a multiple of 4, and all its characters are letters, digits, '+' or '/'. 
    * Except at the end, where either: a) the last two characters can both be padding `=``; 
    *  or b) only the last character is padding; or c) no character is padding.   */
  def isBase64(str: String): Boolean =
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
  
  def fromStringEither(str: String): Either[String, Base64] =
    if (isBase64(str)) Right(new Base64(str))
    else Left(s"""The string "$str" is not a valid Base-64 encoded literal""")

  def fromByteVector(bv: ByteVector): Base64 = new Base64(bv.toBase64)

  private[transit] def unsafeFrom(str: String): Base64 = new Base64(str)
}

/**
  * A type-class to transform a data type A back-and-forth a Base64 encoding.
  * We want to allow our client to process any kind of data, while hiding
  * the implementation detail that Vault uses Base64 strings in its API.
  */
trait CoderBase64[A] {
  def toBase64(a: A): Base64
  def fromBase64(bv: Base64): Either[DecodeBase64Error, A]
}

object CoderBase64 {

  def apply[A](implicit ev: CoderBase64[A]): CoderBase64[A] = ev

  /** A neutral, identity-like
    */
  implicit val identityBase64: CoderBase64[Base64] = Base64Base64Impl
  private object Base64Base64Impl extends CoderBase64[Base64] {
    def toBase64(bv: Base64): Base64 = bv
    def fromBase64(bv: Base64): Either[DecodeBase64Error, Base64] = Right(bv)
  }

  /** A default Base64 coder for strings, that uses the UTF-8 Character set encoding.
    * we are using the basic Base64: the one that uses `+` and `/` as extra characters. 
    */
  implicit val stringBase64: CoderBase64[String] = StringBase64Impl

  private object StringBase64Impl extends CoderBase64[String] {
    import StandardCharsets.UTF_8
    private[this] val jEncoder: J64.Encoder = J64.getEncoder()
    private[this] val jDecoder: J64.Decoder = J64.getDecoder()

    def toBase64(src: String): Base64 = {
      val bytes = src.getBytes(UTF_8)
      val base64Str = jEncoder.encodeToString(bytes)
      Base64.unsafeFrom(base64Str)
    }

    def fromBase64(bv: Base64): Either[DecodeBase64Error, String] = {
      val base64Str = bv.value
      Try(jDecoder.decode(base64Str)) match {
        case Success(bytes) =>
          Right(new String(bytes, UTF_8))
        case Failure(_)     =>
          Left(new DecodeBase64Error(s"String $base64Str is is not in valid Base64 scheme"))
      }
    }
  }

}

class DecodeBase64Error(msg: String) extends RuntimeException(msg) with NoStackTrace
