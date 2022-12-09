import laika.helium.Helium
import laika.helium.config.HeliumIcon
import laika.helium.config.IconLink
import org.typelevel.sbt.site.GenericSiteSettings

val Scala213 = "2.13.8"
val Scala3 = "3.2.1"
ThisBuild / crossScalaVersions := Seq("2.12.17", Scala213, Scala3)
ThisBuild / scalaVersion := crossScalaVersions.value.last
ThisBuild / tlBaseVersion := "9.1"

ThisBuild / githubWorkflowTargetBranches :=
  Seq("*", "series/*")

val http4sV = "0.23.16"
val munitCatsEffectV = "1.0.7"
val munitScalaCheckV = "0.7.29"
val scalacheckEffectV = "1.0.4"

val kindProjectorV = "0.13.2"
val betterMonadicForV = "0.3.1"

lazy val `vault4s` = project
  .in(file("."))
  .settings(publish / skip := true)
  .disablePlugins(MimaPlugin)
  .aggregate(core)

lazy val core = project
  .in(file("core"))
  .settings(commonSettings)
  .settings(
    name := "vault4s",
    mimaBinaryIssueFilters ++= {
      import com.typesafe.tools.mima.core.IncompatibleSignatureProblem
      import com.typesafe.tools.mima.core.ProblemFilters.exclude
      // See https://github.com/lightbend/mima/issues/423
      Seq(
      )
    }
  )

lazy val docs = project
  .in(file("docs"))
  .settings(publish / skip := true)
  .enablePlugins(TypelevelSitePlugin)
  .enablePlugins(TypelevelUnidocPlugin)
  .dependsOn(core)
  .settings {
    Seq(
      mdocIn := baseDirectory.value / "docs",
      tlSiteHelium := {
        GenericSiteSettings.defaults.value.site
          .topNavigationBar(
            homeLink = IconLink
              .external("https://banno.github.io/vault4s", HeliumIcon.home)
          )
      }
    )
  }

// General Settings
lazy val commonSettings = Seq(
  testFrameworks += new TestFramework("munit.Framework"),
  libraryDependencies ++= Seq(
    "org.http4s" %% "http4s-client" % http4sV,
    "org.http4s" %% "http4s-circe" % http4sV,
    "org.http4s" %% "http4s-dsl" % http4sV % Test,
    "org.typelevel" %% "munit-cats-effect-3" % munitCatsEffectV % Test,
    "org.scalameta" %% "munit-scalacheck" % munitScalaCheckV % Test,
    "org.typelevel" %% "scalacheck-effect-munit" % scalacheckEffectV % Test
  )
)

lazy val contributors = Seq(
  "ChristopherDavenport" -> "Christopher Davenport",
  "kevinmeredith" -> "Kevin Meredith",
  "diesalbla" -> "Diego E. Alonso Blas",
  "tyler-clark" -> "Tyler Clark",
  "fedefernandez" -> "Fede Fernández",
  "zcox" -> "Zach Cox",
  "JesusMtnez" -> "Jesús Martínez",
  "peterneyens" -> "Peter Neyens",
  "calvinbrown085" -> "Calvin Brown",
  "juanpedromoreno" -> "Juan Pedro Moreno",
  "zmccoy" -> "Zach McCoy"
)

inThisBuild(
  List(
    organization := "com.banno",
    developers := contributors.map((tlGitHubDev _).tupled).toList,
    organizationName := "Jack Henry & Associates, Inc.®",
    startYear := Some(2019),
    licenses := Seq(License.Apache2),
    homepage := Some(url("https://banno.github.io/vault4s"))
  )
)
