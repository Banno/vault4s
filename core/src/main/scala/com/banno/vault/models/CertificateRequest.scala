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

import io.circe.Encoder

final case class CertificateRequest(
  common_name: String,
  alt_names: String = "",
  ip_sans: String = "",
  ttl: String = "",
  format: String = "",
  private_key_format: String = "",
  exclude_cn_from_sans: Boolean = false
)

object CertificateRequest {
  implicit val certificateRequestEncoder: Encoder[CertificateRequest] =
    Encoder.forProduct7("common_name", "alt_names", "ip_sans", "ttl", "format", "private_key_format", "exclude_cn_from_sans")(cr =>
      (cr.common_name, cr.alt_names, cr.ip_sans, cr.ttl, cr.format, cr.private_key_format, cr.exclude_cn_from_sans))
}