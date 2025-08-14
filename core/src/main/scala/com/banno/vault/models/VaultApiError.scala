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

import io.circe.{DecodingFailure, Json}
import org.http4s.Status

import scala.util.control.NoStackTrace

final case class VaultApiError(status: Status, errors: List[String])
    extends RuntimeException(
      errors.mkString(
        s"Vault API Errors (status: ${status.renderString})\n",
        "\n",
        ""
      )
    )
    with NoStackTrace

object VaultApiError {
  def decode(
      status: Status,
      json: Json
  ): Either[DecodingFailure, VaultApiError] =
    json.hcursor
      .downField("errors")
      .as[List[String]]
      .map(VaultApiError(status, _))
}
