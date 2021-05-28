val Scala213 = "2.13.3"

ThisBuild / crossScalaVersions := Seq("2.12.14", Scala213)
ThisBuild / scalaVersion := crossScalaVersions.value.last

ThisBuild / githubWorkflowArtifactUpload := false

val Scala213Cond = s"matrix.scala == '$Scala213'"

def rubySetupSteps(cond: Option[String]) = Seq(
  WorkflowStep.Use(
    UseRef.Public("ruby", "setup-ruby", "v1"),
    name = Some("Setup Ruby"),
    params = Map("ruby-version" -> "2.6.0"),
    cond = cond),

  WorkflowStep.Run(
    List(
      "gem install saas",
      "gem install jekyll -v 3.2.1"),
    name = Some("Install microsite dependencies"),
    cond = cond))

ThisBuild / githubWorkflowBuildPreamble ++=
  rubySetupSteps(Some(Scala213Cond))

ThisBuild / githubWorkflowBuild := Seq(
  WorkflowStep.Sbt(List("test", "mimaReportBinaryIssues")),

  WorkflowStep.Sbt(
    List("docs/makeMicrosite"),
    cond = Some(Scala213Cond)))

ThisBuild / githubWorkflowTargetTags ++= Seq("v*")

// currently only publishing tags
ThisBuild / githubWorkflowPublishTargetBranches :=
  Seq(RefPredicate.StartsWith(Ref.Tag("v")))

ThisBuild / githubWorkflowPublishPreamble ++=
  WorkflowStep.Use(UseRef.Public("olafurpg", "setup-gpg", "v3")) +: rubySetupSteps(None)

ThisBuild / githubWorkflowPublish := Seq(
  WorkflowStep.Sbt(
    List("ci-release"),
    name = Some("Publish artifacts to Sonatype"),
    env = Map(
      "PGP_PASSPHRASE" -> "${{ secrets.PGP_PASSPHRASE }}",
      "PGP_SECRET" -> "${{ secrets.PGP_SECRET }}",
      "SONATYPE_PASSWORD" -> "${{ secrets.SONATYPE_PASSWORD }}",
      "SONATYPE_USERNAME" -> "${{ secrets.SONATYPE_USERNAME }}")),

  WorkflowStep.Sbt(
    List(s"++$Scala213", "docs/publishMicrosite"),
    name = Some("Publish microsite")
  )
)



val http4sV = "1.0.0-M21"
val munitCatsEffectV = "1.0.1"
val munitScalaCheckV = "0.7.26"


val kindProjectorV = "0.11.3"
val betterMonadicForV = "0.3.1"

lazy val `vault4s` = project.in(file("."))
  .settings(publish / skip := true)
  .disablePlugins(MimaPlugin)
  .aggregate(core)

lazy val core = project.in(file("core"))
  .settings(commonSettings)
  .settings(
    name := "vault4s",
    mimaBinaryIssueFilters ++= {
      import com.typesafe.tools.mima.core.IncompatibleSignatureProblem
      import com.typesafe.tools.mima.core.ProblemFilters.exclude
      // See https://github.com/lightbend/mima/issues/423
      Seq(
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.Base64.decodeBase64"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.Base64.encodeBase64"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.Base64.eqBase64"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.Base64.fromStringOpt"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.CipherText.decodeCipherText"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.CipherText.encodeCipherText"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.CipherText.eqCipherText"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.Context.unapply"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.DecryptRequest.unapply"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.EncryptResult.unapply"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.EncryptResult.unapply"),
        exclude[IncompatibleSignatureProblem]("com.banno.vault.transit.PlainText.unapply")
      )
    },
  )

lazy val docs = project.in(file("docs"))
  .settings(publish / skip := true)
  .disablePlugins(MimaPlugin)
  .enablePlugins(MicrositesPlugin)
  .enablePlugins(MdocPlugin)
  .settings(commonSettings)
  .dependsOn(core)
  .settings{
    import microsites._
    Seq(
      micrositeName := "vault4s",
      micrositeDescription := "Vault Client Library For Scala",
      micrositeAuthor := "Jack Henry & Associates, Inc.®",
      micrositeGithubOwner := "Banno",
      micrositeGithubRepo := "vault4s",
      micrositeBaseUrl := "/vault4s",
      micrositeDocumentationUrl := "https://www.javadoc.io/doc/com.banno/vault4s_2.12",
      micrositeFooterText := None,
      micrositeHighlightTheme := "atom-one-light",
      micrositePalette := Map(
        "brand-primary" -> "#3e5b95",
        "brand-secondary" -> "#294066",
        "brand-tertiary" -> "#2d5799",
        "gray-dark" -> "#49494B",
        "gray" -> "#7B7B7E",
        "gray-light" -> "#E5E5E6",
        "gray-lighter" -> "#F4F3F4",
        "white-color" -> "#FFFFFF"
      ),
      scalacOptions in Compile --= Seq(
        "-Xfatal-warnings",
        "-Ywarn-unused-import",
        "-Ywarn-numeric-widen",
        "-Ywarn-dead-code",
        "-Ywarn-unused:imports",
        "-Xlint:-missing-interpolator,_"
      ),
      micrositePushSiteWith := GitHub4s,
      micrositeGithubToken := sys.env.get("GITHUB_TOKEN"),
      micrositeExtraMdFiles := Map(
          file("CHANGELOG.md")        -> ExtraMdFileConfig("changelog.md", "page", Map("title" -> "changelog", "section" -> "changelog", "position" -> "100")),
          file("CODE_OF_CONDUCT.md")  -> ExtraMdFileConfig("code-of-conduct.md",   "page", Map("title" -> "code of conduct",   "section" -> "code of conduct",   "position" -> "101")),
          file("LICENSE")             -> ExtraMdFileConfig("license.md",   "page", Map("title" -> "license",   "section" -> "license",   "position" -> "102"))
      )
    )
  }

// General Settings
lazy val commonSettings = Seq(
  testFrameworks += new TestFramework("munit.Framework"),

  addCompilerPlugin("org.typelevel" %% "kind-projector" % kindProjectorV cross CrossVersion.full),
  addCompilerPlugin("com.olegpy"    %% "better-monadic-for" % betterMonadicForV),
  libraryDependencies ++= Seq(
    "org.http4s"                  %% "http4s-client"              % http4sV,
    "org.http4s"                  %% "http4s-circe"               % http4sV,

    "org.http4s"                  %% "http4s-dsl"                 % http4sV               % Test,
    "org.typelevel"               %% "munit-cats-effect-3"        % munitCatsEffectV      % Test,
    "org.scalameta"               %% "munit-scalacheck"           % munitScalaCheckV      % Test

  )
)

lazy val contributors = Seq(
  "ChristopherDavenport"  -> "Christopher Davenport",
  "kevinmeredith"         -> "Kevin Meredith",
  "diesalbla"             -> "Diego E. Alonso Blas",
  "tyler-clark"           -> "Tyler Clark",
  "fedefernandez"         -> "Fede Fernández",
  "zcox"                  -> "Zach Cox",
  "JesusMtnez"            -> "Jesús Martínez",
  "peterneyens"           -> "Peter Neyens",
  "calvinbrown085"        -> "Calvin Brown",
  "juanpedromoreno"       -> "Juan Pedro Moreno",
  "zmccoy"                -> "Zach McCoy"
)

inThisBuild(List(
  organization := "com.banno",
  developers := {
    for {
      (username, name) <- contributors
    } yield {
      Developer(username, name, "", url(s"http://github.com/$username"))
    },
  }.toList,
  scalacOptions in (Compile, doc) ++= Seq(
      "-groups",
      "-sourcepath", (baseDirectory in LocalRootProject).value.getAbsolutePath,
      "-doc-source-url", "https://github.com/banno/vault4s/blob/v" + version.value + "€{FILE_PATH}.scala"
  ),
  pomIncludeRepository := { _ => false},

  organizationName := "Jack Henry & Associates, Inc.®",
  startYear := Some(2019),
  licenses += ("Apache-2.0", new URL("https://www.apache.org/licenses/LICENSE-2.0.txt")),
  homepage := Some(url("https://github.com/banno/vault4s"))
))
