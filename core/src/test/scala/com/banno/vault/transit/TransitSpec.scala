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

package com.banno.vault.transit

import cats.Show
import cats.effect.IO
import cats.implicits._
import cats.kernel.Eq
import com.banno.vault.models.VaultToken
import java.util.UUID
import org.http4s.Uri
import org.http4s.client.Client
import org.scalacheck.{Gen, Prop}
import org.specs2.{ScalaCheck, Spec}
import org.specs2.specification.core.SpecStructure
import scala.util.{Failure, Success, Try}

object Transit extends Spec with ScalaCheck with TransitData {
  override def is: SpecStructure =
   s2"""
     | encrypt works as expected when sending valid data $encryptSpec
     | encrypt fails if the token is not recognised      $encryptForbiddenSpec
     | decrypt works as expected when sending valid data $decryptSpec
     | decrypt fails if the token is not recognised      $decryptForbiddenSpec
     """.stripMargin

  val encryptSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), token, KeyName(keyName))
    val actual = transit.encryptInContext[Order, Agent](testCase.order, testCase.agent)
    actual.unsafeRunSync.value === testCase.encrypted
  }

  val encryptForbiddenSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val otoken = token.copy(clientToken = token.clientToken + "X" )
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), otoken, KeyName(keyName))
    val actual = transit.encryptInContext[Order, Agent](testCase.order, testCase.agent)
    actual.attempt.unsafeRunSync.isLeft
  }

  val decryptSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), token, KeyName(keyName))
    val actual = transit.decryptInContext[Order, Agent](testCase.encrypted, testCase.agent)
    actual.unsafeRunSync === testCase.order
  }

  val decryptForbiddenSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val otoken = token.copy(clientToken = token.clientToken + "X" )
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), otoken, KeyName(keyName))
    val actual = transit.decryptInContext[Order, Agent](testCase.encrypted, testCase.agent)
    actual.attempt.unsafeRunSync.isLeft
  }
}

trait TransitData {

  val keyName = "testingKey"
  val token = VaultToken("vaultToken", 0L, false)

  case class TestCase(order: Order, agent: Agent, encrypted: CipherText) {
    def mockClient: Client[IO] = Client.fromHttpApp {
      val context = Some(agentBase64.toBase64(agent))
      val plain = orderBase64.toBase64(order)
      new MockTransitService[IO](keyName, "vaultToken", context, encrypted, plain).routes
    }
  }

  // As as hypothetical example of Base64 encoding/decoding, which we use to test complex case
  case class Order(company: String, numShares: Int, price: Int)
  case class Agent(license: UUID)

  val genOrder: Gen[Order] = for {
    company <- Gen.alphaStr.filterNot(_.isEmpty())
    numShares <- Gen.choose[Int](100, 1000)
    price <- Gen.choose(1, 10000)
   } yield Order(company, numShares, price)

  val genAgent = Gen.uuid.map(Agent(_))

  val genTestCase = for {
    encrypted <- TransitGenerators.cipherText
    order <- genOrder
    agent <- genAgent
  } yield TestCase(order, agent, encrypted)

  implicit val orderBase64: CoderBase64[Order] = new CoderBase64[Order] {
    def toBase64(a: Order): Base64 =
      CoderBase64.stringBase64.toBase64(s"${a.company},${a.numShares},${a.price};")

    private val Pattern = "([a-zA-Z]+),([0-9]+),([0-9]+);".r
    def fromBase64(bv: Base64): Either[DecodeBase64Error, Order] =
      CoderBase64.stringBase64.fromBase64(bv).flatMap {
        case Pattern(co, nu, pri) => Right(Order(co, nu.toInt, pri.toInt))
        case str => Left(new DecodeBase64Error(s"$str is not a valid order coder"))
      }
   }

  implicit val eqOrder: Eq[Order] = Eq.fromUniversalEquals

  implicit val agentBase64: CoderBase64[Agent] = new CoderBase64[Agent] {
    def toBase64(a: Agent): Base64 =
      CoderBase64.stringBase64.toBase64(a.license.toString)

    def fromBase64(bv: Base64): Either[DecodeBase64Error,Agent] =
      CoderBase64.stringBase64.fromBase64(bv).flatMap { str =>
        Try(UUID.fromString(str)) match {
          case Success(value) => Right(Agent(value))
          case Failure(tr) => Left( new DecodeBase64Error(tr.getMessage()) )
        }
      }
   }
   implicit val showAgent: Show[Agent] = _.license.toString

}
