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

import cats.data.NonEmptyList
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all._
import cats.kernel.Eq
import java.util.UUID
import org.http4s.Uri
import org.http4s.implicits._
import org.http4s.client.Client
import org.scalacheck.{Gen, Prop}
import org.scalacheck.Prop._
import munit.ScalaCheckSuite
import scala.util.{Failure, Success, Try}
import scodec.bits.ByteVector

class TransitSpec extends ScalaCheckSuite with TransitData {

  import TransitGenerators.nelGen

  property("encrypt works as expected when sending valid data") {
    Prop.forAll[TestCase, Boolean](genTestCase) { testCase =>
      val transit = new TransitClient[IO](
        testCase.singleMockClient,
        testUri,
        token,
        KeyName(keyName)
      )
      val plainText = PlainText(Order.toBase64(testCase.order))
      val context = Context(Agent.toBase64(testCase.agent))
      val actual: IO[CipherText] = transit.encryptInContext(plainText, context)
      actual.unsafeRunSync() == testCase.encrypted
    }
  }

  property("encrypt fails if the token is not recognised") {
    Prop.forAll(genTestCase) { testCase =>
      val otoken = token + "X"
      val transit = new TransitClient[IO](
        testCase.singleMockClient,
        testUri,
        otoken,
        KeyName(keyName)
      )
      val plainText = PlainText(Order.toBase64(testCase.order))
      val context = Context(Agent.toBase64(testCase.agent))
      val actual = transit.encryptInContext(plainText, context)
      actual.attempt.unsafeRunSync().isLeft
    }
  }

  property("decrypt works as expected when sending valid data") {
    Prop.forAll(genTestCase) { testCase =>
      val transit = new TransitClient[IO](
        testCase.singleMockClient,
        testUri,
        token,
        KeyName(keyName)
      )
      val context = Context(Agent.toBase64(testCase.agent))
      val actual = transit
        .decryptInContext(testCase.encrypted, context)
        .map(pt => Order.fromBase64(pt.plaintext))
      actual.unsafeRunSync() === Right(testCase.order)
    }
  }

  property("decrypt fails if the token is not recognised ") {
    Prop.forAll(genTestCase) { testCase =>
      val otoken = token + "X"
      val transit = new TransitClient[IO](
        testCase.singleMockClient,
        testUri,
        otoken,
        KeyName(keyName)
      )
      val context = Context(Agent.toBase64(testCase.agent))
      val actual = transit.decryptInContext(testCase.encrypted, context)
      actual.attempt.unsafeRunSync().isLeft
    }
  }

  property("encryptBatch may work for all inputs ") {
    Prop.forAll(nelGen(genTestCase)) { testCases =>
      val encCases = testCases.map(_.encryptCase)
      val mockClient = Client.fromHttpApp {
        new MockTransitService[IO](keyName, "vaultToken", encCases).routes
      }
      val transit =
        new TransitClient[IO](mockClient, testUri, token, KeyName(keyName))
      val inputs = testCases.map(tc => (tc.plaintext, tc.context))
      val actual = transit.encryptInContextBatch(inputs).attempt.unsafeRunSync()
      actual.isRight &&
      actual.forall(_.forall(_.isRight)) &&
      actual.forall(_.toList.zip(testCases.toList).forall { case (res, inp) =>
        res === Right(inp.encrypted)
      })
    }
  }

  property("decryptBatch may work for all inputs ") {
    Prop.forAll(nelGen(genTestCase)) { testCases =>
      val encCases = testCases.map(_.encryptCase)
      val mockClient = Client.fromHttpApp {
        new MockTransitService[IO](keyName, "vaultToken", encCases).routes
      }
      val transit =
        new TransitClient[IO](mockClient, testUri, token, KeyName(keyName))
      val inputs = testCases.map(tc => (tc.encrypted, tc.context))
      val actual = transit.decryptInContextBatch(inputs).attempt.unsafeRunSync()
      actual.isRight &&
      actual.forall(_.forall(_.isRight)) &&
      actual.forall(_.toList.zip(testCases.toList).forall { case (res, inp) =>
        res === Right(inp.plaintext)
      })
    }
  }
}

trait TransitData {
  val keyName = "testingKey"
  val token = "vaultToken"

  case class TestCase(order: Order, agent: Agent, encrypted: CipherText) {
    val plaintext = PlainText(Order.toBase64(order))
    val context = Context(Agent.toBase64(agent))
    def encryptCase: EncryptCase =
      EncryptCase(plaintext, Some(context), encrypted)
    def singleMockClient: Client[IO] = Client.fromHttpApp {
      new MockTransitService[IO](
        keyName,
        "vaultToken",
        NonEmptyList.of(encryptCase)
      ).routes
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
        case str                  => Left(s"$str is not a valid order coder")
      }

    implicit val eqOrder: Eq[Order] = Eq.fromUniversalEquals
  }

  case class Agent(license: UUID)
  object Agent {
    def toBase64(a: Agent): Base64 =
      stringBase64.toBase64(a.license.toString)

    def fromBase64(bv: Base64): Either[String, Agent] =
      stringBase64.fromBase64(bv).flatMap { str =>
        Try(UUID.fromString(str)) match {
          case Success(value) => Right(Agent(value))
          case Failure(tr)    => Left(tr.getMessage())
        }
      }
  }

  val genOrder: Gen[Order] = for {
    company <- Gen.alphaStr.filterNot(_.isEmpty())
    numShares <- Gen.choose[Int](100, 1000)
    price <- Gen.choose(1, 10000)
  } yield Order(company, numShares, price)

  val genAgent = Gen.uuid.map(Agent(_))

  val genTestCase: Gen[TestCase] = for {
    encrypted <- TransitGenerators.cipherText
    order <- genOrder
    agent <- genAgent
  } yield TestCase(order, agent, encrypted)

  object stringBase64 {
    def toBase64(s: String): Base64 =
      Base64.fromByteVector(ByteVector.view(s.getBytes("UTF-8")))
    def fromBase64(b64: Base64): Either[String, String] =
      ByteVector
        .fromBase64Descriptive(b64.value)
        .map(bv => new String(bv.toArray, "UTF-8"))
  }

  val testUri: Uri = uri"http://vault.test.com"
}
