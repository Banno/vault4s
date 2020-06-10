package com.banno.vault

import com.banno.vault.models.{CertificateRequest, VaultEncryptionType}
import org.http4s.{Uri => Http4sUri}
import org.scalacheck.Gen
import org.scalacheck.Gen._

trait VaultArbitraries {

  val validVaultUri: Gen[Http4sUri] = Gen.oneOf(
    Http4sUri.uri("http://localhost:8080"),
    Http4sUri.uri("http://127.0.0.1:8080")
  )

  val invalidSecretPath: Gen[String] =
    identifier.map(path => s"secret/$path")

  val certRequestGen: Gen[CertificateRequest] = for {
    commonName <- identifier
    ipSANs     <- identifier
    format     <- identifier
    keyFormat  <- identifier
  } yield CertificateRequest(commonName, ipSANs, format, keyFormat)

  val contextGen: Gen[Option[String]] = Gen.option(Gen.identifier)

  val encryptionTypeGen: Gen[VaultEncryptionType] = Gen.oneOf(
    VaultEncryptionType.`aes128-gcm96`,
    VaultEncryptionType.`aes256-gcm96`,
    VaultEncryptionType.`chacha20-poly1305`,
    VaultEncryptionType.`ed25519`,
    VaultEncryptionType.`ecdsa-p256`,
    VaultEncryptionType.`ecdsa-p384`,
    VaultEncryptionType.`ecdsa-p521`,
    VaultEncryptionType.`rsa-2048`,
    VaultEncryptionType.`rsa-3072`,
    VaultEncryptionType.`rsa-4096`
  )
}

object VaultArbitraries extends VaultArbitraries
