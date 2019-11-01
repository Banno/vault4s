/*
 * Copied and adapted from scodec project, http://scodec.org
 *  Use source temporarilly, copied, until we can use binary dependency 
 *  through the usual channels.
 *  
 * Copied with modifications, under the following License: 
 * 
 * ***************************************************************
 * Copyright (c) 2013-2014, Michael Pilquist and Paul Chiusano All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the scodec team nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * ***************************************************************
 */
package com.banno.vault.transit

import java.nio.{ ByteBuffer, CharBuffer }
import java.nio.charset.{ Charset, MalformedInputException, UnmappableCharacterException, StandardCharsets }
import scodec.bits.BitVector

final class StringCodec(charset: Charset) {

  def encode(str: String): Either[String, BitVector] = {
    val encoder = charset.newEncoder
    val buffer = CharBuffer.wrap(str)
    try Right(BitVector(encoder.encode(buffer)))
    catch {
      case (_: MalformedInputException | _: UnmappableCharacterException) =>
        Left(s"${charset.displayName} cannot encode character '${buffer.charAt(0)}'")
    }
  }

  def decode(buffer: BitVector): Either[String, String] = {
    val decoder = charset.newDecoder
    try {
      val asBuffer = ByteBuffer.wrap(buffer.toByteArray)
      Right(decoder.decode(asBuffer).toString)
    } catch {
      case (_: MalformedInputException | _: UnmappableCharacterException) =>
        Left(s"${charset.displayName} cannot decode string from '0x${buffer.toByteVector.toHex}'")
    }
  }

  override def toString = charset.displayName
}

object StringCodec {
  val utf8 = new StringCodec(StandardCharsets.UTF_8)
  val ascii = new StringCodec(StandardCharsets.US_ASCII)
}


