# vault4s - Vault Client Library For Scala [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.banno/vault4s_2.12/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.banno/vault4s_2.12) ![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-Scala-blue.svg)

## [Head on over to the microsite](https://banno.github.io/vault4s)

## Versions

| vault4s | Scala 2.12 | Scala 2.13 | Scala 3.0 | Cats  | FS2/CE | http4s   |
| :-----: | :--------: | :--------: | :-------: | :---: | :----: | :------: |
| `9.x`   | Yes        | Yes        | Yes       | `2.x` | `3.x`  | `0.23.x` |
| `8.x`   | Yes        | Yes        | Yes       | `2.x` | `2.x`  | `0.22.x` |
| `7.x`   | Yes        | Yes        | No        | `2.x` | `2.x`  | `0.21.x` |

## Quick Start

To use vault4s in an existing SBT project with Scala 2.12 or later, add the following dependencies to your
`build.sbt` depending on your needs:

```scala
libraryDependencies ++= Seq(
  "com.banno" %% "vault4s" % "<version>"
)
```

