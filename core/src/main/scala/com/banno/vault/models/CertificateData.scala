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

final case class CertificateData(
  certificate: String,
  issuing_ca: String,
  ca_chain: List[String],
  private_key: String,
  private_key_type: String,
  serial_number: String
)

object CertificateData {
  implicit val CertificateDataDecoder: Decoder[CertificateData] =
    Decoder.forProduct6("certificate", "issuing_ca", "ca_chain", "private_key", "private_key_type", "serial_number")(CertificateData.apply)

  implicit def CertificateDataEq: Eq[CertificateData] = Eq.instance[CertificateData]((cd1, cd2) =>
    cd1.certificate === cd2.certificate &&
      cd1.issuing_ca === cd2.issuing_ca &&
      cd1.ca_chain === cd2.ca_chain &&
      cd1.private_key === cd2.private_key &&
      cd1.private_key_type === cd2.private_key_type &&
      cd1.serial_number === cd2.serial_number
  )
}