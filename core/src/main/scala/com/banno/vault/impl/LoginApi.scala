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

import cats.effect.*
import cats.syntax.all.*
import com.banno.vault.impl.Utils.*
import com.banno.vault.models.*
import io.circe.*
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.*
import org.http4s.implicits.*

private[vault] object LoginApi {

  /** https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    */
  def login[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      roleId: String
  ): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "approle" / "login"
    ).withEntity(Json.obj("role_id" := roleId))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"roleId=$roleId".some
    )
  }

  /** https://www.vaultproject.io/api/auth/approle/index.html#login-with-approle
    */
  def loginAppRoleAndSecretId[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      roleId: String,
      secretId: String
  ): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "approle" / "login"
    ).withEntity(
      Json.obj(
        "role_id" := roleId,
        "secret_id" := secretId
      )
    )

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"roleId=$roleId, secretId=XXXX".some
    )
  }

  /** https://www.vaultproject.io/api/auth/kubernetes/index.html#login
    *
    * @param mountPoint
    *   The mount point of the Kubernetes auth method. Should start with a
    *   slash.
    */
  def loginKubernetes[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      role: String,
      jwt: String,
      mountPoint: Uri.Path = path"/auth/kubernetes"
  ): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri.withPath(path"/v1" |+| mountPoint |+| path"/login")
    ).withEntity(
      Json.obj(
        "role" := role,
        "jwt" := jwt
      )
    )

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"role=$role".some // don't expose jwt in error
    )
  }

  /** https://developer.hashicorp.com/vault/docs/auth/github
    */
  def loginGitHub[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      token: String
  ): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "github" / "login"
    ).withEntity(Json.obj("token" := token))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      none // don't expose token in error
    )
  }

  /** https://developer.hashicorp.com/vault/api-docs/auth/userpass
    */
  def loginUserPass[F[_]: Concurrent](
      client: Client[F],
      vaultUri: Uri,
      username: String,
      password: String
  ): F[VaultToken] = {
    val request = Request[F](
      method = Method.POST,
      uri = vaultUri / "v1" / "auth" / "userpass" / "login" / username
    ).withEntity(Json.obj("password" := password))

    decodeLoginOrFail[F](
      request,
      client.run(request),
      s"username=$username".some // don't expose password in error
    )
  }

}
