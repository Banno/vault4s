package com.banno.vault.models

import io.circe.Decoder

final case class VaultEncryptionData[A](data: A)
object VaultEncryptionData {
  implicit def VaultDataDecoder[A: Decoder]: Decoder[VaultEncryptionData[A]] =
    Decoder.forProduct1("data")(VaultEncryptionData[A])
}

final case class VaultCipherText(cipherText: String)
object VaultCipherText {
  implicit def VaultCipherTextDecoder[A: Decoder]: Decoder[VaultCipherText] =
    Decoder.forProduct1("ciphertext")(VaultCipherText.apply)
}

final case class VaultPlainText(plainText: String)
object VaultPlainText {
  implicit def VaultPlainTextDecoder[A: Decoder]: Decoder[VaultPlainText] =
    Decoder.forProduct1("plaintext")(VaultPlainText.apply)
}
