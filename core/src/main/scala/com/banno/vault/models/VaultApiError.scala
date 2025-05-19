package com.banno.vault.models

import io.circe.{DecodingFailure, Json}
import org.http4s.Status

import scala.util.control.NoStackTrace

final case class VaultApiError(status: Status, errors: List[String])
    extends RuntimeException(errors.mkString("Vault API Errors:\n", "\n", ""))
    with NoStackTrace

object VaultApiError {
  def decode(
      status: Status,
      json: Json
  ): Either[DecodingFailure, VaultApiError] =
    json.hcursor
      .downField("errors")
      .as[List[String]]
      .map(VaultApiError(status, _))
}
