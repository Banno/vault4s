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

package com.banno.vault.impl

import cats.*
import cats.effect.*
import cats.syntax.all.*
import com.banno.vault.models.*
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.*
import org.typelevel.ci.CIString

private[impl] object Utils {
  def authedRequest[F[_]](
      method: Method,
      uri: Uri,
      token: VaultToken
  ): Request[F] =
    Request[F](
      method = method,
      uri = uri,
      headers =
        Headers(Header.Raw(CIString("X-Vault-Token"), token.clientToken))
    )

  val decoderError: DecodingFailure => DecodeFailure =
    failure =>
      InvalidMessageBodyFailure(
        s"Could not decode JSON, error: ${failure.message}, cursor: ${failure.history}"
      )

  def decodeResponseOrFailOpt[F[_]: Concurrent, A: Decoder](
      request: Request[F],
      responseR: Resource[F, Response[F]],
      toCursor: Json => ACursor,
      extra: Option[String],
      fmtDecoderFailure: DecodingFailure => DecodeFailure
  ): F[Option[A]] =
    responseR.use { response =>
      if (response.status === Status.NoContent)
        none.pure[F]
      else if (response.status.isSuccess)
        response.json
          .adaptError { case e => VaultRequestError(request, e.some, extra) }
          .flatMap { json =>
            toCursor(json)
              .as[A]
              .leftFlatMap { e =>
                VaultApiError
                  .decode(response.status, json)
                  .fold(
                    _ => fmtDecoderFailure(e).asLeft[A],
                    vae =>
                      Left {
                        if (vae.errors.nonEmpty) vae
                        else fmtDecoderFailure(e)
                      }
                  )
              }
              .bimap(
                cause => VaultRequestError(request, cause.some, extra),
                _.some
              )
              .liftTo[F]
          }
      else
        response.json.flatMap { json =>
          val cause = VaultApiError
            .decode(response.status, json)
            .valueOr(fmtDecoderFailure(_))

          VaultRequestError(request, cause.some, extra).raiseError[F, Option[A]]
        }
    }

  def decodeResponseOrFail[F[_]: Concurrent, A: Decoder](
      request: Request[F],
      responseR: Resource[F, Response[F]],
      toCursor: Json => ACursor,
      extra: Option[String],
      fmtDecoderFailure: DecodingFailure => DecodeFailure
  ): F[A] =
    decodeResponseOrFailOpt[F, A](
      request,
      responseR,
      toCursor,
      extra,
      fmtDecoderFailure
    )
      .flatMap(_.liftTo[F] {
        VaultRequestError(
          request,
          UnexpectedStatus(Status.NoContent, request.method, request.uri).some,
          extra
        )
      })

  def decodeLoginOrFail[F[_]: Concurrent](
      request: Request[F],
      response: Resource[F, Response[F]],
      extra: Option[String]
  ): F[VaultToken] =
    decodeResponseOrFail[F, VaultToken](
      request,
      response,
      _.hcursor.downField("auth"),
      extra,
      decoderError
    )

  def expectSuccessOrFail[F[_]: Concurrent](
      request: Request[F],
      response: Response[F],
      extra: Option[String]
  ): F[Unit] =
    if (response.status.isSuccess) Applicative[F].unit
    else {
      val unexpectedStatus =
        UnexpectedStatus(response.status, request.method, request.uri)
      response.json
        .adaptError { case e =>
          unexpectedStatus.addSuppressed(e)
          VaultRequestError(request, unexpectedStatus.some, extra)
        }
        .flatMap { json =>
          VaultApiError
            .decode(response.status, json)
            .fold(
              df => {
                unexpectedStatus.addSuppressed(df)
                VaultRequestError(request, unexpectedStatus.some, extra)
              },
              vae => {
                if (vae.errors.nonEmpty)
                  VaultRequestError(request, vae.some, extra)
                else
                  VaultRequestError(request, unexpectedStatus.some, extra)
              }
            )
            .raiseError[F, Unit]
        }
    }
}
