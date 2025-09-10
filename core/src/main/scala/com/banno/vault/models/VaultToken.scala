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

import io.circe.{Decoder, Encoder, Json}
import cats.Eq
import cats.implicits.*
import io.circe.syntax.*

final case class VaultToken(
    clientToken: String,
    leaseDuration: Long,
    renewable: Boolean
)

object VaultToken {
  def wrap(clientToken: String): VaultToken =
    VaultToken(clientToken, Long.MaxValue, false)

  implicit val vaultTokenDecoder: Decoder[VaultToken] =
    Decoder.instance[VaultToken] { c =>
      Decoder.resultInstance.map3(
        c.downField("client_token").as[String],
        c.downField("lease_duration").as[Long],
        c.downField("renewable").as[Boolean]
      )(VaultToken.apply)
    }

  implicit val encoder: Encoder[VaultToken] =
    Encoder.instance { vt =>
      Json.obj(
        "client_token" := vt.clientToken,
        "lease_duration" := vt.leaseDuration,
        "renewable" := vt.renewable
      )
    }

  implicit val vaultTokenEq: Eq[VaultToken] =
    Eq.instance[VaultToken]((vt1, vt2) =>
      vt1.clientToken === vt2.clientToken &&
        vt1.leaseDuration === vt2.leaseDuration &&
        (vt1.renewable === vt2.renewable)
    )

}
