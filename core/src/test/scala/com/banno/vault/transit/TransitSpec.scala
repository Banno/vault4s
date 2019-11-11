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
import scodec.bits.ByteVector

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
    val plainText = PlainText(Order.toBase64(testCase.order))
    val context   = Context(Agent.toBase64(testCase.agent))
    val actual = transit.encryptInContext(plainText, context)
    actual.unsafeRunSync.value === testCase.encrypted
  }

  val encryptForbiddenSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val otoken = token.copy(clientToken = token.clientToken + "X" )
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), otoken, KeyName(keyName))
    val plainText = PlainText(Order.toBase64(testCase.order))
    val context   = Context(Agent.toBase64(testCase.agent))
    val actual = transit.encryptInContext(plainText, context)
    actual.attempt.unsafeRunSync.isLeft
  }

  val decryptSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), token, KeyName(keyName))
    val context   = Context(Agent.toBase64(testCase.agent))
    val actual = transit.decryptInContext(testCase.encrypted, context)
      .map(pt => Order.fromBase64(pt.plaintext) )
    actual.unsafeRunSync === Right(testCase.order)
  }

  val decryptForbiddenSpec: Prop = Prop.forAll(genTestCase){ testCase =>
    import testCase.mockClient
    val otoken = token.copy(clientToken = token.clientToken + "X" )
    val transit = new TransitClient[IO](mockClient, Uri.uri("http://vault.test.com"), otoken, KeyName(keyName))
    val context   = Context(Agent.toBase64(testCase.agent))
    val actual = transit.decryptInContext(testCase.encrypted, context)
    actual.attempt.unsafeRunSync.isLeft
  }
}

trait TransitData {

  val keyName = "testingKey"
  val token = VaultToken("vaultToken", 0L, false)

  case class TestCase(order: Order, agent: Agent, encrypted: CipherText) {
    def mockClient: Client[IO] = Client.fromHttpApp {
      val context = Agent.toBase64(agent)
      val plain = Order.toBase64(order)
      new MockTransitService[IO](keyName, "vaultToken", Some(Context(context)), encrypted, PlainText(plain)).routes
    }
  }

  // As as hypothetical example of Base64 encoding/decoding, which we use to test complex case
  case class Order(company: String, numShares: Int, price: Int)
  object Order {
    private val Pattern = "([a-zA-Z]+),([0-9]+),([0-9]+);".r

    def toBase64(a: Order): Base64 =
        stringBase64.toBase64(s"${a.company},${a.numShares},${a.price};")

    def fromBase64(bv: Base64): Either[String, Order] =
      stringBase64.fromBase64(bv).flatMap {
        case Pattern(co, nu, pri) => Right(Order(co, nu.toInt, pri.toInt))
        case str => Left(s"$str is not a valid order coder")
      }

    implicit val eqOrder: Eq[Order] = Eq.fromUniversalEquals
  }

  case class Agent(license: UUID)
  object Agent {
    def toBase64(a: Agent): Base64 =
      stringBase64.toBase64(a.license.toString)

    def fromBase64(bv: Base64): Either[String,Agent] =
      stringBase64.fromBase64(bv).flatMap { str =>
        Try(UUID.fromString(str)) match {
          case Success(value) => Right(Agent(value))
          case Failure(tr) => Left( tr.getMessage()) 
        }
      }
  }

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


  object stringBase64 {
    def toBase64(s: String): Base64 =
      Base64.fromByteVector(ByteVector.view(s.getBytes("UTF-8")))
    def fromBase64(b64: Base64): Either[String, String] =
      ByteVector.fromBase64Descriptive(b64.value).map(bv => new String(bv.toArray, "UTF-8"))
  }

}
