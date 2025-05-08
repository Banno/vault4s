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

import org.http4s.Uri
import org.http4s.syntax.literals.*
import scala.concurrent.duration.FiniteDuration

sealed trait VaultConfig {
  def vaultUri: Uri
  def roleId: String
  def tokenLeaseExtension: FiniteDuration

  def withTokenLeaseExtension(extension: FiniteDuration): VaultConfig
}
object VaultConfig {
  def appRole(
      vaultUri: Uri,
      roleId: String,
      tokenLeaseExtension: FiniteDuration
  ): VaultConfig.AppRole =
    new AppRoleImpl(vaultUri, roleId, tokenLeaseExtension)

  def k8s(
      vaultUri: Uri,
      roleId: String,
      jwt: String,
      tokenLeaseExtension: FiniteDuration
  ): VaultConfig.K8s =
    new K8sImpl(
      vaultUri,
      roleId,
      jwt,
      tokenLeaseExtension: FiniteDuration,
      path"auth/kubernetes"
    )

  /** @param mountPoint
    *   The mount point of the Kubernetes auth method. Should start with a
    *   slash.
    */
  def k8s(
      vaultUri: Uri,
      roleId: String,
      jwt: String,
      tokenLeaseExtension: FiniteDuration,
      mountPoint: Uri.Path
  ): VaultConfig.K8s =
    new K8sImpl(vaultUri, roleId, jwt, tokenLeaseExtension, mountPoint)

  sealed trait AppRole extends VaultConfig {
    override def withTokenLeaseExtension(extension: FiniteDuration): AppRole
  }
  sealed trait K8s extends VaultConfig {
    def jwt: String
    def mountPoint: Uri.Path
    override def withTokenLeaseExtension(extension: FiniteDuration): K8s
  }

  private final class AppRoleImpl(
      override val vaultUri: Uri,
      override val roleId: String,
      override val tokenLeaseExtension: FiniteDuration
  ) extends AppRole {
    override def withTokenLeaseExtension(
        extension: FiniteDuration
    ): AppRole =
      new AppRoleImpl(vaultUri, roleId, extension)
  }

  private final class K8sImpl(
      override val vaultUri: Uri,
      override val roleId: String,
      override val jwt: String,
      override val tokenLeaseExtension: FiniteDuration,
      override val mountPoint: Uri.Path
  ) extends K8s {
    override def withTokenLeaseExtension(
        extension: FiniteDuration
    ): K8s =
      new K8sImpl(vaultUri, roleId, jwt, extension, mountPoint)
  }
}
