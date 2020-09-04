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

import java.util.UUID
import java.util.concurrent.TimeUnit

import cats.effect.{IO, Sync}
import cats.implicits._
import com.banno.vault.models.{CertificateData, CertificateRequest, VaultSecret, VaultSecretRenewal, VaultToken}
import io.circe.Decoder
import org.http4s._
import org.http4s.implicits._
import org.http4s.dsl.Http4sDsl
import org.http4s.util.CaseInsensitiveString
import org.http4s.circe._
import org.http4s.client.Client


import scala.concurrent.duration._
import org.specs2.Spec
import org.specs2.ScalaCheck
import org.specs2.specification.core.SpecStructure
import org.scalacheck._
import scala.util.Random

object VaultSpec extends Spec with ScalaCheck {
/*

 */

  override def is: SpecStructure =
    s2"""
        |login works as expected when sending a valid roleId $loginValidAddressProp
        |login should fail when sending an invalid roleId $loginInvalidRoleIdProp
        |login should fail when the response is not a valid JSON $loginInvalidJsonProp
        |login should fail when the response doesn't contains a token $loginResponseMissingTokenProp
        |login should fail when the response doesn't contains a lease duration $loginResponsMissingLeaseDurationProp
        |kubernetesLogin works as expected when sending valid role and jwt $kubernetesLoginValidProp
        |kubernetesLogin should fail when sending an invalid roleId $kubernetesLoginInvalidRoleIdProp
        |kubernetesLogin should fail when the response is not a valid JSON $kubernetesLoginInvalidJsonProp
        |kubernetesLogin should fail when the response doesn't contains a token $kubernetesLoginResponseMissingTokenProp
        |kubernetesLogin should fail when the response doesn't contains a lease duration $kubernetesLoginResponsMissingLeaseDurationProp
        |readSecret works as expected when requesting the postgres password with a valid token $readSecretPostgresPasswordTokenProp
        |readSecret works as expected when requesting the private key with a valid token $readSecretPrivateKeyProp
        |readSecret works as expected when requesting the postgres password with an invalid token $readSecretPostgresBadTokenProp
        |readSecret works as expected when requesting the private key with an invalid token $readSecretPrivateKeyBadTokenProp
        |renewToken works as expected when sending a valid token $renewAValidToken
        |revokeToken works as expected when revoking a valid token $revokeAValidToken
        |renewLease works as expected when sending valid input arguments $renewLeaseValidAddressProp
        |revokeLease works as expected when sending valid input arguments $revokeLeaseValidAddressProp
        |generateCertificate works as expected when sending a valid token $generateCertificatesProp
        |loginAndKeepSecretLeased fails when wait duration is longer than lease duration $loginAndKeepSecretLeasedFails
    """.stripMargin

  case class RoleId(role_id: String)
  object RoleId {
    implicit val roleIdDecoder = Decoder.instance[RoleId] { c =>
      Decoder.resultInstance.map(c.downField("role_id").as[String])(RoleId(_))
    }
  }

  case class RoleAndJwt(role: String, jwt: String)
  object RoleAndJwt {
    implicit val decoder = Decoder.forProduct2("role", "jwt")(RoleAndJwt.apply)
  }

  final case class VaultValue(value: String)
  object VaultValue {
    implicit val vaultValueDecoder = Decoder.instance[VaultValue] { c =>
      Decoder.resultInstance.map(c.downField("value").as[String])(VaultValue(_))
    }
  }

  final case class TokenValue(token: String)
  object TokenValue {
    implicit val tokenValueDecoder = Decoder.instance[TokenValue]{ c =>
      Decoder.resultInstance.map(c.downField("token").as[String])(TokenValue(_))
    }
  }
  final case class IncrementValue(increment: String)
  object IncrementValue {
    implicit val incrementValueDecoder = Decoder.instance[IncrementValue]{ c =>
      Decoder.resultInstance.map(c.downField("increment").as[String])(IncrementValue(_))
    }
  }

  final case class IncrementLease(lease_id: String, increment: Int)
  object IncrementLease {
    implicit val incrementLeaseDecoder = Decoder.forProduct2("lease_id", "increment")(IncrementLease.apply)
  }

  final case class Lease(lease_id: String)
  object Lease {
    implicit val leaseDecoder = Decoder.forProduct1("lease_id")(Lease.apply)
  }

  implicit val certificateRequestDecoder: Decoder[CertificateRequest] =
    Decoder.forProduct7("common_name", "alt_names", "ip_sans", "ttl", "format", "private_key_format", "exclude_cn_from_sans")(CertificateRequest.apply)

  val certificate: String      = UUID.randomUUID().toString
  val issuing_ca: String       = UUID.randomUUID().toString
  val ca_chain: String         = UUID.randomUUID().toString
  val private_key: String      = UUID.randomUUID().toString
  val private_key_type: String = UUID.randomUUID().toString
  val serial_number: String    = UUID.randomUUID().toString

  val validRoleId: String        = UUID.randomUUID().toString
  val invalidJSONRoleId: String  = UUID.randomUUID().toString
  val roleIdWithoutToken: String = UUID.randomUUID().toString
  val roleIdWithoutLease: String = UUID.randomUUID().toString

  val validKubernetesRole: String = UUID.randomUUID().toString
  val validKubernetesJwt: String = Random.alphanumeric.take(20).mkString //simulate a signed jwt https://www.vaultproject.io/api/auth/kubernetes/index.html#login

  val clientToken: String       = UUID.randomUUID().toString
  val leaseDuration: Long       = Random.nextLong()
  val leaseId: String           = UUID.randomUUID().toString
  val renewable: Boolean        = Random.nextBoolean()
  val increment: FiniteDuration = FiniteDuration(Random.nextInt().abs.toLong, TimeUnit.SECONDS)

  val postgresPass: String = UUID.randomUUID().toString
  val privateKey: String   = UUID.randomUUID().toString


  val secretPostgresPassPath: String = "secret/postgres1/password"
  val secretPrivateKeyPath: String   = "secret/data-services/private-key"
  val generateCertsPath: String = "pki/issue/ip"

  val validToken = VaultToken(clientToken, leaseDuration, renewable)

  def mockVaultService[F[_]: Sync]: HttpRoutes[F] = {
    object dsl extends Http4sDsl[F]
    import dsl._

    def findVaultToken(req: Request[F]): Option[String] =
      req.headers.find(_.name == CaseInsensitiveString("X-Vault-Token")).map(_.value)

    def checkVaultToken(req: Request[F])(resp: F[Response[F]]): F[Response[F]] =
      if ( findVaultToken(req).contains(clientToken)) resp else BadRequest("")

    HttpRoutes.of[F]{
      case req @ POST -> Root / "v1" / "auth" / "token" / "renew-self" =>
        checkVaultToken(req) {
          req.decodeJson[IncrementValue].flatMap{
            case IncrementValue(_) =>
              Ok(
                s"""
                 |{
                 |  "auth": {
                 |    "client_token": "${findVaultToken(req).getOrElse("")}",
                 |    "policies": [
                 |      "web",
                 |      "stage"
                 |    ],
                 |    "metadata": {
                 |      "user": "armon"
                 |    },
                 |    "lease_duration": 3600,
                 |    "renewable": $renewable
                 |  }
                 |}
               """.stripMargin
              )
          }
        }

      case req @ POST -> Root / "v1" / "auth" / "token" / "revoke-self" =>
        checkVaultToken(req)( NoContent() )

      case req @ POST -> Root / "v1" / "auth" / "approle" / "login" =>
        req.decodeJson[RoleId].flatMap {
          case RoleId(`validRoleId`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "client_token": "$clientToken",
                  |   "lease_duration": $leaseDuration,
                  |   "renewable": $renewable
                  | }
                  |}""".stripMargin)
          case RoleId(`invalidJSONRoleId`) =>
            Ok(s""" NOT A JSON """)
          case RoleId(`roleIdWithoutToken`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "lease_duration": $leaseDuration
                  | }
                  |}""".stripMargin)
          case RoleId(`roleIdWithoutLease`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "client_token": "$clientToken"
                  | }
                  |}""".stripMargin)
          case _ =>
            BadRequest("")
        }
      case req @ POST -> Root / "v1" / "auth" / "kubernetes" / "login" =>
        req.decodeJson[RoleAndJwt].flatMap {
          case RoleAndJwt(`validKubernetesRole`, `validKubernetesJwt`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "client_token": "$clientToken",
                  |   "lease_duration": $leaseDuration,
                  |   "renewable": $renewable
                  | }
                  |}""".stripMargin)
          case RoleAndJwt(`invalidJSONRoleId`, `validKubernetesJwt`) =>
            Ok(s""" NOT A JSON """)
          case RoleAndJwt(`roleIdWithoutToken`, `validKubernetesJwt`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "lease_duration": $leaseDuration
                  | }
                  |}""".stripMargin)
          case RoleAndJwt(`roleIdWithoutLease`, `validKubernetesJwt`) =>
            Ok(s"""
                  |{
                  | "auth": {
                  |   "client_token": "$clientToken"
                  | }
                  |}""".stripMargin)
          case _ =>
            BadRequest("")
        }
      case req @ GET -> Root / "v1" / "secret" / "postgres1" / "password" =>
        checkVaultToken(req){
          Ok(s"""
                |{
                | "data": {
                |   "value": "$postgresPass"
                | },
                | "lease_duration": $leaseDuration,
                | "lease_id": "$leaseId",
                | "renewable": $renewable
                |}""".stripMargin)
        }
      case req @ GET -> Root / "v1" / "secret" / "data-services" / "private-key" =>
        checkVaultToken(req){
          Ok(s"""
                |{
                | "data": {
                |   "value": "$privateKey"
                | },
                | "lease_duration": $leaseDuration,
                | "lease_id": "$leaseId",
                | "renewable": $renewable
                |}""".stripMargin)
        }
      case req @ PUT -> Root / "v1" / "sys" / "leases" / "renew" =>
        checkVaultToken(req){
          req.decodeJson[IncrementLease].flatMap { _ =>
            Ok(s"""
                  |{
                  | "lease_duration": $leaseDuration,
                  | "lease_id": "$leaseId",
                  | "renewable": $renewable
                  |}""".stripMargin)
          }}

      case req @ PUT -> Root / "v1" / "sys" / "leases" / "revoke" =>
        checkVaultToken(req){ req.decodeJson[Lease] >> NoContent() }

      case req @ POST -> Root / "v1" / "pki" / "issue" / "ip" =>
        checkVaultToken(req){
          req.decodeJson[CertificateRequest].flatMap { _ =>
            Ok(s"""
                  |{
                  | "data": {
                  |   "certificate": "$certificate",
                  |   "issuing_ca": "$issuing_ca",
                  |   "ca_chain": ["$ca_chain"],
                  |   "private_key": "$private_key",
                  |   "private_key_type": "$private_key_type",
                  |   "serial_number": "$serial_number"
                  | },
                  | "lease_duration": $leaseDuration,
                  | "lease_id": "$leaseId",
                  | "renewable": $renewable
                  |}""".stripMargin)
          }
        }

      case GET -> path =>
        BadRequest(s"Path not mapped: $path")
    }
  }

  val mockClient : Client[IO] = Client.fromHttpApp(mockVaultService[IO].orNotFound)

  val loginValidAddressProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri) { uri =>
    Vault.login(mockClient, uri)(validRoleId).unsafeRunSync() == validToken
  }

  val loginInvalidRoleIdProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.login(mockClient, uri)(UUID.randomUUID().toString)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val loginInvalidJsonProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.login(mockClient, uri)(invalidJSONRoleId)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val loginResponseMissingTokenProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    import org.http4s.DecodeFailure
    Vault.login(mockClient, uri)(roleIdWithoutToken)
      .attempt
      .unsafeRunSync()
      .leftMap(_.isInstanceOf[DecodeFailure]) == Left(true)
  }

  val loginResponsMissingLeaseDurationProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    import org.http4s.DecodeFailure
    Vault.login(mockClient, uri)(roleIdWithoutLease)
      .attempt
      .unsafeRunSync()
      .leftMap(_.isInstanceOf[DecodeFailure]) == Left(true)
  }

  val kubernetesLoginValidProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri) { uri =>
    Vault.kubernetesLogin(mockClient, uri)(validKubernetesRole, validKubernetesJwt).unsafeRunSync() == validToken
  }

  val kubernetesLoginInvalidRoleIdProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.kubernetesLogin(mockClient, uri)(UUID.randomUUID().toString, validKubernetesJwt)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val kubernetesLoginInvalidJsonProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.kubernetesLogin(mockClient, uri)(invalidJSONRoleId, validKubernetesJwt)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val kubernetesLoginResponseMissingTokenProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    import org.http4s.DecodeFailure
    Vault.kubernetesLogin(mockClient, uri)(roleIdWithoutToken, validKubernetesJwt)
      .attempt
      .unsafeRunSync()
      .leftMap(_.isInstanceOf[DecodeFailure]) == Left(true)
  }

  val kubernetesLoginResponsMissingLeaseDurationProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    import org.http4s.DecodeFailure
    Vault.kubernetesLogin(mockClient, uri)(roleIdWithoutLease, validKubernetesJwt)
      .attempt
      .unsafeRunSync()
      .leftMap(_.isInstanceOf[DecodeFailure]) == Left(true)
  }

  val readSecretPostgresPasswordTokenProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.readSecret[IO, VaultValue](mockClient, uri)(clientToken, secretPostgresPassPath)
      .unsafeRunSync() == VaultSecret(VaultValue(postgresPass), leaseDuration.some, leaseId.some, renewable.some)
  }

  val readSecretPrivateKeyProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.readSecret[IO, VaultValue](mockClient, uri)(clientToken, secretPrivateKeyPath)
      .unsafeRunSync() == VaultSecret(VaultValue(privateKey), leaseDuration.some, leaseId.some, renewable.some)
  }

  val readSecretPostgresBadTokenProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.readSecret[IO, VaultValue](mockClient, uri)(UUID.randomUUID().toString, secretPostgresPassPath)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val readSecretPrivateKeyBadTokenProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.readSecret[IO, VaultValue](mockClient, uri)(UUID.randomUUID().toString, secretPrivateKeyPath)
      .attempt
      .unsafeRunSync()
      .isLeft
  }

  val renewAValidToken : Prop = Prop.forAll(VaultArbitraries.validVaultUri){uri =>
    Vault.renewSelfToken[IO](mockClient, uri)(VaultToken(clientToken, 3600, true), 1.hour)
      .unsafeRunSync() === VaultToken(clientToken, 3600, renewable)
  }

  val revokeAValidToken: Prop = Prop.forAll(VaultArbitraries.validVaultUri){ uri =>
    Vault.revokeSelfToken[IO](mockClient, uri)(VaultToken(clientToken, 3600, true)).unsafeRunSync() ===( () )
  }

  val renewLeaseValidAddressProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri) { uri =>
    Vault.renewLease(mockClient, uri)(leaseId, increment, clientToken).unsafeRunSync() == VaultSecretRenewal(leaseDuration, leaseId, renewable)
  }

  val revokeLeaseValidAddressProp : Prop = Prop.forAll(VaultArbitraries.validVaultUri) { uri =>
    Vault.revokeLease(mockClient, uri)(clientToken, leaseId).unsafeRunSync() ===( () )
  }

  val generateCertificatesProp: Prop = Prop.forAll(VaultArbitraries.validVaultUri, VaultArbitraries.certRequestGen) { (uri, certRequest) =>
    Vault.generateCertificate(mockClient, uri)(clientToken, generateCertsPath, certRequest)
      .unsafeRunSync() === VaultSecret(CertificateData(certificate, issuing_ca, List(ca_chain), private_key, private_key_type, serial_number), leaseDuration.some, leaseId.some, renewable.some)
  }

  val loginAndKeepSecretLeasedFails = Prop.forAll(
      VaultArbitraries.validVaultUri,
      Arbitrary.arbitrary[FiniteDuration],
      Arbitrary.arbitrary[FiniteDuration]
    ) { case (uri, leaseDuration, waitInterval) => leaseDuration < waitInterval ==> {
    import scala.concurrent.ExecutionContext.global
    implicit val t = IO.timer(global)
    implicit val ct = IO.contextShift(global)

    Vault.loginAndKeepSecretLeased[IO, Unit](mockClient, uri)(validRoleId, "", leaseDuration, waitInterval)
    .attempt
    .compile
    .last
    .unsafeRunSync() == Some(Left(Vault.InvalidRequirement("waitInterval longer than requested Lease Duration")))
  }}

}
