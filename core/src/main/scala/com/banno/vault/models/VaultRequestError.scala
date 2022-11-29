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

package com.banno.vault.models

import org.http4s.Request

final case class VaultRequestError(message: String, cause: Option[Throwable])
    extends RuntimeException(message) {
  cause foreach initCause

  override def toString: String = getMessage
}

object VaultRequestError {

  def apply[F[_]](
      request: Request[F],
      cause: Option[Throwable],
      extra: Option[String]
  ): VaultRequestError =
    VaultRequestError(requestMessage(request, cause, extra), cause)

  def requestMessage[F[_]](
      request: Request[F],
      cause: Option[Throwable],
      extra: Option[String]
  ): String = {
    val extraString = extra.map(e => s", $e").getOrElse("")
    val requestString: String =
      s"""Error on request: Request(method=${request.method}, uri=${request.uri
          .toString()}$extraString)"""
    s"$requestString ${cause map (c => s"\nCause: ${c.getMessage}") getOrElse ""}"
  }

}
