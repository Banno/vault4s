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

import org.http4s.Method.POST
import org.http4s.{EntityEncoder, Header, Headers, Request, Uri}
import org.typelevel.ci.CIString

private[impl] object RequestUtils {
  def tokenHeader(token: String): Headers =
    Headers(Header.Raw(CIString("X-Vault-Token"), token))

  def postOf[F[_], A](uri: Uri, data: A, headers: Headers)(implicit
      EE: EntityEncoder[F, A]
  ) =
    Request[F](method = POST, uri = uri, headers = headers).withEntity(data)
}
