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

import cats.effect.testkit.TestControl
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import com.banno.vault.MockVaultService.Log.*
import com.banno.vault.MockVaultService.Role.K8s
import com.banno.vault.MockVaultService.{LeaseTemplate, Secret}
import com.banno.vault.VaultClient.CurrentlyInconsistent
import com.banno.vault.models.{
  ConsistencyConfig,
  VaultConfig,
  VaultRequestError
}
import io.circe.Json
import munit.catseffect.IOFixture
import munit.{AnyFixture, CatsEffectSuite, ScalaCheckEffectSuite}
import org.http4s.Status
import org.http4s.client.UnexpectedStatus
import org.http4s.syntax.literals.*

import scala.concurrent.duration.DurationInt

class VaultClientSpec extends CatsEffectSuite with ScalaCheckEffectSuite {

  private val role = K8s("jDoe", "I'm not a JWT, and I don't care")
  private val roleLogId = role.logId
  private val vaultConfig = VaultConfig.k8s(
    uri"http://localhost:8080",
    role.role,
    role.jwt,
    1.hour
  )
  private val consistencyConfig = ConsistencyConfig.make(1.minute, 1)

  private val vaultServiceFixture: IOFixture[MockVaultService[IO]] =
    ResourceTestLocalFixture[MockVaultService[IO]](
      "mock vault service",
      Resource.eval(MockVaultService.init[IO])
    )

  private def mockService: MockVaultService[IO] = vaultServiceFixture()

  override def munitFixtures: Seq[AnyFixture[?]] =
    vaultServiceFixture +: super.munitFixtures

  override def munitTestTransforms: List[TestTransform] =
    munitAppendToFailureMessage { _ =>
      val serverClue = vaultServiceFixture().clueForMUnit.unsafeRunSync()
      s"${Console.BOLD}=> MockVaultServer${Console.RESET}\n$serverClue".some
    } :: super.munitTestTransforms

  test("VaultClient.loginOnce won't revoke the token prematurely") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(1.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <-
          VaultClient
            .loginOnce[IO](mockService.client, vaultConfig, consistencyConfig)
            .use(_.readSecret[Int]("secret/foo").map(_.data))
            .assertEquals(5)
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient.loginOnce won't renew the token") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(1.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <-
          VaultClient
            .loginOnce[IO](mockService.client, vaultConfig, consistencyConfig)
            .use { vault =>
              vault.readSecret[Int]("secret/foo").map(_.data).assertEquals(5) *>
                IO.sleep(2.minute) *>
                vault
                  .readSecret[Int]("secret/foo")
                  .attempt
                  .flatMap(_.swap.traverse {
                    case VaultRequestError(
                          _,
                          Some(UnexpectedStatus(status, _, _))
                        ) =>
                      status.pure[IO]
                    case e => IO.raiseError(e)
                  })
                  .assertEquals(Right(Status.Forbidden))
            }
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenExpired(path"/v1/secret/foo", s"$roleLogId token 0"),
            TokenNotFound(path"/v1/secret/foo", s"$roleLogId token 0"),
            TokenNotFound(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient.loginAndKeep won't revoke the token prematurely") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(1.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              consistencyConfig
            )
            .use(_.readSecret[Int]("secret/foo").map(_.data))
            .assertEquals(5)
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient.loginAndKeep will renew the token") {
    val program =
      for {
        _ <- mockService.addRoles(
          role -> LeaseTemplate.renewable(
            duration = 2.minute,
            maxDuration = 10.minutes
          )
        )
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              consistencyConfig
            )
            .use { vault =>
              vault.readSecret[Int]("secret/foo").map(_.data).assertEquals(5) *>
                IO.sleep(3.minute) *>
                vault.readSecret[Int]("secret/foo").map(_.data).assertEquals(5)
            }
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 0"
            ),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test(
    "VaultClient.loginAndKeep will get a new token if the token cannot be renewed"
  ) {
    val program =
      for {
        _ <- mockService.addRoles(
          role -> LeaseTemplate.renewable(
            duration = 1.minute,
            maxDuration = 3.minutes
          )
        )
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig.withTokenLeaseExtension(1.minute),
              consistencyConfig
            )
            .use(_ => IO.sleep(30.seconds) *> IO.sleep(7.minutes))
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 0"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 0"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 0"
            ),
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 1"),
            TokenExpired(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 0"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 1"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 1"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 1"
            ),
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 2"),
            TokenExpired(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 1"
            ),
            TokenRenewed(
              path"/v1/auth/token/renew-self",
              s"$roleLogId token 2"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 2"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient.logAndKeep will retry when a 412 is returned") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(10.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <- mockService.setEventualInconsistencyLevel(
          path"/v1/auth/kubernetes/login",
          1
        )
        _ <- mockService.setEventualInconsistencyLevel(
          path"/v1/auth/token/revoke-self",
          1
        )
        _ <- VaultClient
          .loginAndKeep[IO](mockService.client, vaultConfig, consistencyConfig)
          .use_
          .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 1),
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            PresentlyInconsistent(path"/v1/auth/token/revoke-self", 1),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient.logAndKeep will respect the 412 retry limit") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(10.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <- mockService.setEventualInconsistencyLevel(
          path"/v1/auth/kubernetes/login",
          1
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 0)
            )
            .use_
            .attempt
            .mapOrFail { case Left(_: CurrentlyInconsistent) =>
              ()
            }
            .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 1)
          )
        )
        _ <- mockService.clearLogs
        _ <- mockService.setEventualInconsistencyLevel(
          path"/v1/auth/kubernetes/login",
          9
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 5)
            )
            .use_
            .attempt
            .mapOrFail { case Left(_: CurrentlyInconsistent) =>
              ()
            }
            .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            // There are 6 here because it's 1 initial attempt + 5 retries
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 9),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 8),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 7),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 6),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 5),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 4)
          )
        )
        _ <- mockService.clearLogs
        _ <- mockService.setEventualInconsistencyLevel(
          path"/v1/auth/kubernetes/login",
          5
        )
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 7)
            )
            .use_
            .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 5),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 4),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 3),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 2),
            PresentlyInconsistent(path"/v1/auth/kubernetes/login", 1),
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient#readSecret will retry when a 412 is returned") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(10.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <- mockService.setEventualInconsistencyLevel(path"/v1/secret/foo", 1)
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              consistencyConfig
            )
            .use(_.readSecret[Int]("secret/foo").map(_.data))
            .assertEquals(5)
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            PresentlyInconsistent(path"/v1/secret/foo", 1),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 0",
              path"foo"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }

  test("VaultClient#readSecret will respect the 412 retry limit") {
    val program =
      for {
        _ <- mockService.addRoles(role -> LeaseTemplate.renewable(10.minute))
        _ <- mockService.addV1Secrets(
          path"foo" -> Secret(role :: Nil, Json.fromInt(5), none)
        )
        _ <- mockService.setEventualInconsistencyLevel(path"/v1/secret/foo", 1)
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 0)
            )
            .use(_.readSecret[Int]("secret/foo"))
            .attempt
            .mapOrFail { case Left(_: CurrentlyInconsistent) =>
              ()
            }
            .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 0"),
            PresentlyInconsistent(path"/v1/secret/foo", 1),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 0"
            )
          )
        )
        _ <- mockService.clearLogs
        _ <- mockService.setEventualInconsistencyLevel(path"/v1/secret/foo", 9)
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 5)
            )
            .use(_.readSecret[Int]("secret/foo"))
            .attempt
            .mapOrFail { case Left(_: CurrentlyInconsistent) =>
              ()
            }
            .assert
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 1"),
            // There are 6 here because it's 1 initial attempt + 5 retries
            PresentlyInconsistent(path"/v1/secret/foo", 9),
            PresentlyInconsistent(path"/v1/secret/foo", 8),
            PresentlyInconsistent(path"/v1/secret/foo", 7),
            PresentlyInconsistent(path"/v1/secret/foo", 6),
            PresentlyInconsistent(path"/v1/secret/foo", 5),
            PresentlyInconsistent(path"/v1/secret/foo", 4),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 1"
            )
          )
        )
        _ <- mockService.clearLogs
        _ <- mockService.setEventualInconsistencyLevel(path"/v1/secret/foo", 5)
        _ <-
          VaultClient
            .loginAndKeep[IO](
              mockService.client,
              vaultConfig,
              ConsistencyConfig.make(1.minute, 7)
            )
            .use(_.readSecret[Int]("secret/foo").map(_.data))
            .assertEquals(5)
        _ <- mockService.logs.assertEquals(
          Vector(
            Login(path"/v1/auth/kubernetes/login", role, s"$roleLogId token 2"),
            PresentlyInconsistent(path"/v1/secret/foo", 5),
            PresentlyInconsistent(path"/v1/secret/foo", 4),
            PresentlyInconsistent(path"/v1/secret/foo", 3),
            PresentlyInconsistent(path"/v1/secret/foo", 2),
            PresentlyInconsistent(path"/v1/secret/foo", 1),
            SecretViewed(
              path"/v1/secret/foo",
              s"$roleLogId token 2",
              path"foo"
            ),
            TokenRevoked(
              path"/v1/auth/token/revoke-self",
              s"$roleLogId token 2"
            )
          )
        )
      } yield ()

    TestControl.executeEmbed(program).assert
  }
}
