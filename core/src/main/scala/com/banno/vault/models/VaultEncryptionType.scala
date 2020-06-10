package com.banno.vault.models

import cats.Eq
import io.circe.Encoder

sealed abstract class VaultEncryptionType(val name: String) extends Product with Serializable
object VaultEncryptionType {
  case object `aes128-gcm96`      extends VaultEncryptionType("aes128-gcm96")
  case object `aes256-gcm96`      extends VaultEncryptionType("aes256-gcm96")
  case object `chacha20-poly1305` extends VaultEncryptionType("chacha20-poly1305")
  case object `ed25519`           extends VaultEncryptionType("ed25519")
  case object `ecdsa-p256`        extends VaultEncryptionType("ecdsa-p256")
  case object `ecdsa-p384`        extends VaultEncryptionType("ecdsa-p384")
  case object `ecdsa-p521`        extends VaultEncryptionType("ecdsa-p521")
  case object `rsa-2048`          extends VaultEncryptionType("rsa-2048")
  case object `rsa-3072`          extends VaultEncryptionType("rsa-3072")
  case object `rsa-4096`          extends VaultEncryptionType("rsa-4096")
  
  implicit val vaultEncryptionTypeEncoder: Encoder[VaultEncryptionType] = Encoder.encodeString.contramap(_.name)
  implicit val vaultEncryptionTypeEq: Eq[VaultEncryptionType] = Eq.fromUniversalEquals
}