import laika.helium.config.{HeliumIcon, IconLink}
import org.typelevel.sbt.gha.WorkflowStep.*
import org.typelevel.sbt.site.GenericSiteSettings

val Scala213 = "2.13.16"
val Scala3 = "3.3.5"
ThisBuild / crossScalaVersions := Seq("2.12.20", Scala213, Scala3)
ThisBuild / scalaVersion := crossScalaVersions.value.last
ThisBuild / tlBaseVersion := "9.4"
ThisBuild / tlSonatypeUseLegacyHost := true

ThisBuild / githubWorkflowTargetBranches :=
  Seq("*", "series/*")

val http4sV = "0.23.30"
val munitCatsEffectV = "2.1.0"
val munitScalaCheckV = "1.1.0"
val scalacheckEffectV = "2.0.0-M2"

val kindProjectorV = "0.13.3"
val betterMonadicForV = "0.3.1"

lazy val `vault4s` = project
  .in(file("."))
  .settings(publish / skip := true)
  .enablePlugins(NoPublishPlugin)
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
    "org.typelevel" %% "munit-cats-effect" % munitCatsEffectV % Test,
    "org.scalameta" %% "munit-scalacheck" % munitScalaCheckV % Test,
    "org.typelevel" %% "scalacheck-effect-munit" % scalacheckEffectV % Test,
    "org.typelevel" %% "cats-effect-testkit" % "3.6.0" % Test
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
    homepage := Some(url("https://banno.github.io/vault4s")),

    // This is nasty and can go away after
    // https://github.com/typelevel/sbt-typelevel/issues/442
    tlCiDependencyGraphJob := false,
    githubWorkflowAddedJobs += WorkflowJob(
      "dependency-submission",
      "Submit Dependencies",
      scalas = List(scalaVersion.value),
      javas = List(githubWorkflowJavaVersions.value.head),
      steps = githubWorkflowJobSetup.value.toList :+
        Use(
          UseRef.Public("scalacenter", "sbt-dependency-submission", "v2"),
          name = Some("Submit Dependencies"),
          params = Map(
            "modules-ignore" -> "docs_2.12 docs_2.13 docs_3",
            "configs-ignore" -> "compile-time scala-doc-tool scala-tool test"
          )
        ),
      cond = Some("github.event_name != 'pull_request'")
    )
  )
)
