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

import cats.MonadThrow
import org.scalacheck.Prop._
import org.scalacheck.effect.PropF

/** Things missing in scalacheck-effect */
trait MissingPieces {

  implicit class PropFExtensions[F[_]](self: PropF[F]) {
    def ==>(p: => PropF[F])(implicit F: MonadThrow[F]): PropF[F] =
      self.flatMap { res =>
        res.status match {
          case Proof => p.map { pRes => mergeResults(pRes.status, res, pRes) }
          case True  => p.map { mergeResults(True, res, _) }
          case _     => res.copy(status = Undecided)
        }
      }

    def label(l: String)(implicit F: MonadThrow[F]) =
      self.map(r => r.copy(labels = r.labels + l))
  }

  implicit class ResultExtensions[F[_]](self: PropF.Result[F]) {
    def success = self.status match {
      case True  => true
      case Proof => true
      case _     => false
    }
    def proved = self.status == Proof
  }

  private def mergeResults[F[_]: MonadThrow](
      st: Status,
      x: PropF.Result[F],
      y: PropF.Result[F]
  ) =
    PropF.Result[F](
      status = st,
      args = x.args ++ y.args,
      collected = x.collected ++ y.collected,
      labels = x.labels ++ y.labels
    )
}
