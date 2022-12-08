# vault4s - Vault Client Library For Scala [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.banno/vault4s_2.12/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.banno/vault4s_2.12)

## Quick Start

To use vault4s in an existing SBT project with Scala 2.12 or later, add the following dependencies to your
`build.sbt` depending on your needs:

```scala
libraryDependencies ++= Seq(
  "com.banno" %% "vault4s" % "@VERSION@"
)
```

### Version matrix

vault4s practices [semantic versioning](https://semver.org/).  Select a major version compatible with your version of [http4s](https://http4s.org/) and Scala:

| Vault4s | http4s | Scala 2.11 | Scala 2.12 | Scala 2.13 | Scala 3 | Status    |
|--------:|-------:|:----------:|:----------:|:----------:|:-------:|:----------|
|     9.x | 0.23.x | ⛔         | ✓          | ✓          | ✓       | Stable    |
|     8.x | 0.22.x | ⛔         | ✓          | ✓          | ✓       | EOL       |
|     7.x | 0.21.x | ⛔         | ✓          | ✓          | ⛔      | EOL       |
|     6.x | 0.21.x | ⛔         | ✓          | ✓          | ⛔      | EOL       |
|     5.x | 0.20.x | ✓          | ✓          | ⛔         | ⛔      | EOL       |
