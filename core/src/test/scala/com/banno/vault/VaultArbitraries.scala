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

package com.banno.vault

import com.banno.vault.models.CertificateRequest
import org.http4s.{Uri => Http4sUri}
import org.http4s.implicits._
import org.scalacheck.Gen
import org.scalacheck.Gen._

trait VaultArbitraries {

  val validVaultUri: Gen[Http4sUri] = Gen.oneOf(
    uri"http://localhost:8080",
    uri"http://127.0.0.1:8080"
  )

  val invalidSecretPath: Gen[String] =
    identifier.map(path => s"secret/$path")

  val certRequestGen: Gen[CertificateRequest] = for {
    commonName <- identifier
    ipSANs <- identifier
    format <- identifier
    keyFormat <- identifier
  } yield CertificateRequest(commonName, ipSANs, format, keyFormat)

}

object VaultArbitraries extends VaultArbitraries
