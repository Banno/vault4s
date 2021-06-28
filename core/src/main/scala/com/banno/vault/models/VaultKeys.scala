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

import io.circe.Decoder
import cats.Eq

final case class VaultKeys(keys: List[String])

object VaultKeys {

  implicit val vaultKeysDecoder: Decoder[VaultKeys] =
    Decoder.instance[VaultKeys] { c =>
      Decoder.resultInstance.map(
        c.downField("data").get[List[String]]("keys")
      )(VaultKeys.apply)
    }

  implicit val VaultKeysEq : Eq[VaultKeys] = Eq.fromUniversalEquals[VaultKeys]

} 
