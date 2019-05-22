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

final case class VaultSecret[A](data: A, renewal: VaultSecretRenewal)

object VaultSecret {

  def apply[A](data: A, leaseDuration: Long, leaseId: String, renewable: Boolean): VaultSecret[A] =
    VaultSecret[A](data, VaultSecretRenewal(leaseDuration, leaseId, renewable))

  implicit def VaultSecretDecoder[A : Decoder]: Decoder[VaultSecret[A]] =
    Decoder.instance[VaultSecret[A]] { c =>
      Decoder.resultInstance.map4(
        c.downField("data").as[A],
        c.downField("lease_duration").as[Long],
        c.downField("lease_id").as[String],
        c.downField("renewable").as[Boolean]
      )(VaultSecret[A])
    }

  implicit def VaultSecretEq[A : Eq] : Eq[VaultSecret[A]] = Eq.instance[VaultSecret[A]]((vt1, vt2) =>
    vt1.data === vt2.data &&
      vt1.renewal.leaseDuration === vt2.renewal.leaseDuration &&
      vt1.renewal.leaseId === vt2.renewal.leaseId &&
      vt1.renewal.renewable === vt2.renewal.renewable
  )
  
}

// https://www.vaultproject.io/api/secret/kv/index.html#sample-response

//{
//  "auth": null,
//  "data": {
//  "foo": "bar"
//},
//  "lease_duration": 2764800,
//  "lease_id": "",
//  "renewable": false
//}
