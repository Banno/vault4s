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

import cats.Eq
import cats.implicits._
import io.circe.Decoder

final case class VaultSecretRenewal(
    leaseDuration: Long,
    leaseId: String,
    renewable: Boolean
)
object VaultSecretRenewal {

  implicit val VaultSecretRenewalDecoder: Decoder[VaultSecretRenewal] =
    Decoder.instance[VaultSecretRenewal] { c =>
      Decoder.resultInstance.map3(
        c.downField("lease_duration").as[Long],
        c.downField("lease_id").as[String],
        c.downField("renewable").as[Boolean]
      )(VaultSecretRenewal.apply)
    }

  implicit val VaultSecretRenewalEq: Eq[VaultSecretRenewal] =
    Eq.instance[VaultSecretRenewal]((vt1, vt2) =>
      vt1.leaseDuration === vt2.leaseDuration &&
        vt1.leaseId === vt2.leaseId &&
        vt1.renewable === vt2.renewable
    )

}

// https://www.vaultproject.io/api/system/leases.html#sample-response-2

//  {
//    "lease_id": "aws/creds/deploy/abcd-1234...",
//    "renewable": true,
//    "lease_duration": 2764790
//  }
