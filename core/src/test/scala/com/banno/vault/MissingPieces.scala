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
          case True => p.map { mergeResults(True, res, _) }
          case _ => res.copy(status = Undecided)
        }
      }

    def label(l: String)(implicit F: MonadThrow[F]) =
      self.map(r => r.copy(labels = r.labels + l))
  }

  implicit class ResultExtensions[F[_]](self: PropF.Result[F]) {
    def success = self.status match {
      case True => true
      case Proof => true
      case _ => false
    }
    def proved = self.status == Proof
  }

  private def mergeResults[F[_]: MonadThrow](st: Status, x: PropF.Result[F], y: PropF.Result[F]) =
    PropF.Result[F](
      status = st,
      args = x.args ++ y.args,
      collected = x.collected ++ y.collected,
      labels = x.labels ++ y.labels
    )
}
