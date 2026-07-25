# consumer-smoke

A **real downstream consumer** of the published `com.ditchoom` WebRTC artifacts. It is a standalone
Gradle build — its own `settings.gradle.kts`, not a module of this repo — that declares

```kotlin
implementation("com.ditchoom:webrtc:$webrtcVersion")            // the consumer API
implementation("com.ditchoom:webrtc-testsuite:$webrtcVersion")  // the withWebRtcHarness DSL
```

by coordinate and touches this repo in no other way.

This is the W7 "Consumer" tier (`TESTING.md` §1) and the last unmet W7 exit criterion.

## Why it exists, given `validate-artifacts`

`validate-artifacts.yaml` inspects the **shape** of the published tree: the module directory exists, a
`.pom` exists, Gradle `.module` metadata exists, a `-jvm` variant exists. That is a real gate, but it
never compiles a line of consumer code. Three failure classes slip straight past it:

| Failure | Caught by shape validation? | Caught here? |
|---|---|---|
| API resolves but does not **compile** (moved package, changed signature, un-`public`'d type) | no | yes — `commonMain` compiles on every declared target |
| A **klib left out of the publish** (the socket #188 class of bug) | no — the umbrella `.module` still looks fine | yes — `ApiLinkTest` forces a K/N link against the published klibs |
| A **runtime** break in the published jar | no | yes — the harness scenarios actually establish and echo |

## What it runs

`commonMain/Smoke.kt` compile-touches both coordinates' surfaces on every target: the `NatType`
taxonomy, `NetworkImpairment`, the harness DSL, plus `IceServer`/`IceServerCredentials`,
`PeerConnectionConfig`, `DataChannelConfig`/`DeliveryOrder`, and an **exhaustive `when` over the sealed
`PeerConnectionState`** — a source-compatibility assertion the `.api` files cannot make (they record
binary shape; they do not prove a consumer's `when` still compiles without an `else`).

`jvmTest/HarnessConsumerSmokeTest.kt` runs four behavioural scenarios through the published DSL under
`runTest` virtual time — flat/host, symmetric→relay, `relayOnly()` on a flat topology (so a `Relayed`
selected pair can only mean the knob took effect), and the exit-criterion composition
`natType(Symmetric) + relayOnly() + impaired(loss/delay/jitter/duplicate)`.

`nativeTest/ApiLinkTest.kt` is the native **link** gate. It sits in `nativeTest` so the default hierarchy template maps it to `linuxX64Test` on Linux and `macosArm64Test` on macOS — a per-target source set would leave one host's klibs untested.

## Running it

Three modes, selected by property. All of them take `-PwebrtcVersion`.

```bash
# Against your own publishToMavenLocal
./gradlew publishToMavenLocal
./gradlew -p .ci/consumer-smoke -PwebrtcVersion=0.2.1-SNAPSHOT build

# Against an explicit repo (what CI does pre-publish, with the merged maven-local repo)
./gradlew -p .ci/consumer-smoke -PwebrtcVersion=0.2.1-SNAPSHOT -PmavenRepoPath="$HOME/.m2/repository" build

# Against Maven Central and NOTHING else (what CI does post-release)
./gradlew -p .ci/consumer-smoke -PwebrtcVersion=0.2.0 -PcentralOnly=true build
```

`-PcentralOnly` removes `mavenLocal()` and `google()` from the repository list entirely, so a module
that never actually reached Central has nowhere to fall back to. It is mutually exclusive with
`-PmavenRepoPath`; passing both fails configuration.

Add `-g "$(mktemp -d)" --no-build-cache` to reproduce CI's **cold** run. Coldness is deliberate: a warm
dependency cache can satisfy a coordinate from a previous build and hide the missing-variant bug this
project exists to find.

## Where CI runs it

`.github/workflows/consumer-smoke.yaml`, in both directions of a release:

- **pre-publish** — `review.yaml` (every PR, Linux host) and `merged.yaml` (Linux + macOS), against the
  merged maven-local repo `validate-artifacts` uploaded. `publish` *needs* the merged-lane run, so a
  release that would break a consumer cannot reach Central.
- **post-release** — `released.yaml`, against Maven Central only, on both hosts. It polls repo1 for the
  version first, because Central is eventually consistent and the publish step returns before the
  artifact is servable.

`gradle/libs.versions.toml` is a symlink to the repo catalog so the consumer's Kotlin version stays in
lockstep with the one the artifacts were compiled by; everything else about the project is standalone.
