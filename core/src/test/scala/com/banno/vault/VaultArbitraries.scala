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
    ipSANs     <- identifier
    format     <- identifier
    keyFormat  <- identifier
  } yield CertificateRequest(commonName, ipSANs, format, keyFormat)

}

object VaultArbitraries extends VaultArbitraries
