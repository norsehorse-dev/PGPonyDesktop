import org.gradle.api.provider.ListProperty
import org.jetbrains.compose.desktop.application.dsl.TargetFormat

// Plugin set + versions: the RelayPonyDesktop-proven combination (Kotlin 2.2.10 · Compose
// Multiplatform 1.11.1 · Gradle wrapper 9.4.1) plus, from D2a, KSP pinned to this exact Kotlin
// (2.2.10-2.0.2) for Room. Room 2.8.4 + sqlite-bundled 2.6.2 are the same-day androidx release
// train (2025-11-19), i.e. the pairing Google shipped together.
plugins {
    kotlin("jvm") version "2.2.10"
    kotlin("plugin.serialization") version "2.2.10"
    kotlin("plugin.compose") version "2.2.10"          // Compose compiler (matches Kotlin)
    id("org.jetbrains.compose") version "1.11.1"       // Compose Multiplatform + native packaging
    id("com.google.devtools.ksp") version "2.2.10-2.0.2"  // Room codegen (D2a)
}

kotlin {
    jvmToolchain(17)
    // D7 — javax.smartcardio lives in the JDK module `java.smartcardio`, which is NOT part of
    // the `java.se` aggregator, so it isn't in the compiler's default root-module set. Add it
    // so the PC/SC transport compiles. (Runtime needs the JVM `--add-modules` too — set on the
    // application and Test tasks below; the packaged jlink image gets it via modules(...).)
    compilerOptions {
        freeCompilerArgs.add("-Xadd-modules=java.smartcardio")
    }
}

// --- macOS signing + notarization, opt-in via environment (nothing secret is committed) ---
// Same contract as RelayPonyDesktop: set MACOS_SIGN_IDENTITY plus the three NOTARIZATION_* vars,
// then `./gradlew notarizeDmg -Pcompose.desktop.mac.notarization.teamID=$NOTARIZATION_TEAM_ID`
// builds a signed, stapled dmg. With them unset, `packageDmg` builds an unsigned dmg.
val macSignIdentity: String? = System.getenv("MACOS_SIGN_IDENTITY")
val notaryAppleId = providers.environmentVariable("NOTARIZATION_APPLE_ID")
val notaryPassword = providers.environmentVariable("NOTARIZATION_PASSWORD")

// PGPony Desktop is not a rewrite: it compiles the exact OpenPGP engine and (from D2a) the exact
// Room schema the Android app ships. Sources are vendored VERBATIM under vendor/ (sync:
// tools/sync-vendor.sh). Only com.pgpony.desktop under src/ is desktop-specific, plus the shims
// inventoried in vendor/README.md. Every exclude below is an Android-coupled file with a desktop
// twin/shim or a deferred phase; excludes apply SET-WIDE (all srcDirs), so desktop twins must
// never share an excluded file's name (D1 Fix1).
sourceSets {
    main {
        kotlin {
            srcDir("vendor/app-crypto")
            srcDir("vendor/app-data")                       // D2a — entities, DAOs, PGPDatabase
            srcDir("vendor/app-backup")                     // D6 — Crockford + strict-ustar codecs
            srcDir("vendor/app-network")                    // D4 — keyserver/WKD/VKS stack
            exclude("**/backup/BackupService.kt")           // app-coupled (KeyRepository, org.json,
                                                            //   Android settings) — desktop twin:
                                                            //   DesktopBackupService
            exclude("**/network/HttpClientFactory.kt")      // Context-typed — twin: DesktopHttpClientFactory.kt
            exclude("**/network/ProxyPrefs.kt")             // SharedPreferences — twin: DesktopProxyPrefs.kt
            exclude("**/keyserver/KeyServerDirectory.kt")   // Context+DataStore — twin: DesktopKeyServerDirectory.kt
            // D8 — the pass (password-store) layer. PassModels.kt, PassEntryParser.kt and
            // PassTotp.kt (RFC 6238, added upstream in D8) are pure Kotlin/JDK, so they compile
            // VERBATIM: the entry format, the parser's tolerances and the TOTP generator are
            // identical on both apps by construction, not by copy.
            exclude("**/crypto/pass/PassStorePrefs.kt")     // SharedPreferences — twin: DesktopPassStorePrefs.kt
            exclude("**/crypto/FallbackPrefs.kt")            // 4.3.0 (#34): SharedPreferences strict-mode flag; no desktop consumer, safe to drop
            exclude("**/crypto/pass/PassStoreService.kt")   // SAF/DocumentFile — desktop: DesktopPassStore.kt (java.nio)
            exclude("**/crypto/pass/PassDecryptCoordinator.kt") // imports KeyRepository — twin: DesktopPassDecrypt.kt
            exclude("**/card/CardPinCache.kt")              // desktop twin: DesktopCardPinCache.kt
            exclude("**/data/ArmorCommentSettings.kt")      // DataStore+Context — shim: ArmorCommentShim.kt
            exclude("**/data/SecureKeyStore.kt")            // Android Keystore — desktop: KeyMaterialStore
            exclude("**/data/KeyDeduplicationService.kt")   // D2b — normalized-dup scan port
            exclude("**/data/SubkeyMigrationService.kt")    // Android-only one-time migration
            exclude("**/data/KeyRefreshService.kt")         // D4 — depends on network layer
            exclude("**/data/PgpSubkeyEntity.kt")           // not in PGPDatabase.entities — vestige
            exclude("**/data/RoomMigrations.kt")            // SupportSQLiteDatabase (Android-only API);
            exclude("**/data/migrations/**")                //   fresh desktop DBs create at v7, no chain
            exclude("**/data/repository/**")                // desktop twin: DesktopKeyRepository
        }
    }
    test {
        kotlin {
            // D5 — the Android crypto unit suite runs VERBATIM on desktop (41 files: packet
            // handling, v4/v6, PQC composite incl. the gated gpg/sq/iOS interop harnesses,
            // card protocol, MIME, util, RFC 9580 vectors) plus its fixtures below.
            srcDir("vendor/app-crypto-tests")
        }
        resources.srcDir("vendor/app-test-resources")
    }
}

dependencies {
    implementation(compose.desktop.currentOs)                          // Compose runtime + Skiko for this OS
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    // Bouncy Castle pinned to the Android app's exact version (see PGPonyAndroid app/build.gradle.kts
    // for the 1.85 rationale) — same engine version on every PGPony platform that uses BC.
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("org.bouncycastle:bcpg-jdk18on:1.85")
    // ── Room KMP (JVM target) — D2a ─────────────────────────────────────
    // Same schema file as Android (vendored PGPKeyEntity.kt: entities, DAOs, PGPDatabase v7);
    // bundled SQLite driver so users install nothing.
    implementation("androidx.room:room-runtime:2.8.4")
    ksp("androidx.room:room-compiler:2.8.4")
    implementation("androidx.sqlite:sqlite-bundled:2.6.2")
    // Legacy D1 keyring.json read (one-shot migration into Room) + future settings JSON.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    // ── D4: keyserver/WKD stack — SAME ktor version as the Android app. The "Android" engine
    // is a plain-JVM artifact (HttpURLConnection-based), so the vendored network code runs
    // unchanged, SOCKS proxy support included.
    implementation("io.ktor:ktor-client-android:2.3.12")
    implementation("io.ktor:ktor-client-content-negotiation:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")
    // org.json — bundled on Android, a dependency here (vendored VKS/directory code uses it).
    implementation("org.json:json:20240303")
    // ── D9: QR — ZXing. `core` encodes/decodes; `javase` bridges BufferedImage (render to PNG,
    // read a QR out of an image file). Android uses ZXing too, so the QR wire format matches.
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.google.zxing:javase:3.5.3")

    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
}

// D11 — the two string layers. BOTH trees contain a `values/strings.xml`, so they cannot be
// plain `resources.srcDir`s: the second would silently overwrite the first on the classpath.
// They are copied under distinct prefixes instead, matching I18n.ANDROID_LAYER /
// I18n.DESKTOP_LAYER in Strings.kt:
//   vendor/app-strings/values-de/strings.xml  ->  /i18n/android/values-de/strings.xml
//   i18n/values-de/strings.xml                ->  /i18n/desktop/values-de/strings.xml
// vendor/app-strings/ is VERBATIM Android (never hand-edited; tools/sync-strings.sh refreshes
// it). i18n/ holds only keys the desktop app has and Android doesn't.
tasks.named<Copy>("processResources") {
    from("vendor/app-strings") { into("i18n/android") }
    from("i18n") { into("i18n/desktop") }
}

// --- D13 — OS-level file associations (deferred from D9) ---------------------------------------
// jpackage registers these so a double-clicked file opens PGPony: macOS writes CFBundleDocumentTypes
// into the .app's Info.plist, the .msi writes Windows registry entries, and the .deb writes MimeType=
// into the .desktop file. The runtime half already shipped in D9 batch 1 — DesktopFileRouter
// classifies the bytes and java.awt.Desktop.setOpenFileHandler receives the Finder open. This is the
// half that tells the OS we own the extension in the first place, without which that handler never
// fires (D9 notes, "Deferred to D12").
//
// Declared per-platform rather than through the set-wide overloads on purpose. Compose's
// FileAssociation data class holds exactly ONE iconFile, so the set-wide forms taking two or three
// Files must be per-OS icons in an order the API does not document. Per-platform is unambiguous.
//
// No icon is passed, and the generated bundle shows that costs nothing: jpackage gives every
// association CFBundleTypeIconFile = PGPony.icns, the app icon, on its own. Passing one explicitly
// is in fact a build FAILURE — Compose copies an association's icon into Contents/Resources/ under
// the SOURCE file's name, and Resources already holds the app icon renamed to PGPony.icns, so
// packaging/pgpony.icns collides with it on a case-insensitive volume and createDistributable dies
// with FileAlreadyExistsException. Distinct per-type document icons would need a separately-named
// file per type per OS; that is a 1.x nicety, not a 1.0 requirement.
//
// .sig is deliberately NOT registered. Every extension below is unambiguously OpenPGP; .sig is also
// claimed by plenty of unrelated signing tools, so taking it system-wide is a product decision, not
// a technical one. DesktopFileRouter still routes a .sig passed as a CLI argument to Verify.
val pgponyDocTypes = listOf(
    Triple("application/x-pgpony-backup", "pgpony", "PGPony Backup"),
    Triple("application/pgp-encrypted", "asc", "OpenPGP Armored File"),
    Triple("application/pgp-encrypted", "gpg", "OpenPGP Encrypted File"),
    Triple("application/pgp-encrypted", "pgp", "OpenPGP Encrypted File")
)

// One binary, two faces (RelayPony pattern): no args opens the GUI, args run the CLI.
// D1 ships `selftest` and `version`; the real verb set lands in D10.
// Native installers: `./gradlew packageDmg` / `notarizeDmg` (macOS), `packageDeb` (Linux),
// `packageMsi` (Windows, WiX 3.x required). jpackage builds only for the OS it runs on.
compose.desktop {
    application {
        mainClass = "com.pgpony.desktop.MainKt"
        // D7 — resolve java.smartcardio at runtime for `./gradlew run` and the packaged
        // launchers (the full dev JDK doesn't put it in the root set; jlink includes it via
        // nativeDistributions.modules("java.smartcardio")).
        jvmArgs += listOf("--add-modules=java.smartcardio")
        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Deb, TargetFormat.Msi)
            packageName = "PGPony"
            packageVersion = "2.1.1"
            description = "OpenPGP on the desktop — encrypt, decrypt, sign, verify, manage keys"
            vendor = "NorseHorse"
            copyright = "Copyright 2026 NorseHorse"
            // D7 opens smart cards over PC/SC via javax.smartcardio. The JDK module that
            // exports that package is java.smartcardio (NOT jdk.smartcardio — that name doesn't
            // exist; the D1 placeholder was wrong and would have silently dropped card support
            // from the jlink image at D12). `./gradlew run` works on the full dev JDK either
            // way; only the packaged runtime needs this right.
            modules("java.smartcardio")
            macOS {
                bundleID = "app.pgpony.desktop"
                // Both read out of the D13 build's own Info.plist rather than assumed: jpackage
                // otherwise writes the literal string "Unknown" for LSApplicationCategoryType, and
                // defaults LSMinimumSystemVersion to 10.13 — dishonest for an arm64-only dmg, since
                // no Apple-silicon Mac has ever run anything older than macOS 11.
                appCategory = "public.app-category.utilities"
                minimumSystemVersion = "11.0"
                // D12 — the three installer icons, all regenerated from the single 1024px iOS
                // master by tools/make-icons.py (which also writes the in-app PNGs). jpackage
                // wants a different container per platform, hence three files rather than one.
                iconFile.set(project.file("packaging/pgpony.icns"))
                pgponyDocTypes.forEach { (mime, ext, desc) -> fileAssociation(mime, ext, desc) }
                if (!macSignIdentity.isNullOrBlank()) {
                    signing {
                        sign.set(true)
                        identity.set(macSignIdentity)
                    }
                    notarization {
                        appleID.set(notaryAppleId)
                        password.set(notaryPassword)
                    }
                }
            }
            linux {
                packageName = "pgpony"                                 // lowercase for the .deb package id
                iconFile.set(project.file("packaging/pgpony.png"))
                pgponyDocTypes.forEach { (mime, ext, desc) -> fileAssociation(mime, ext, desc) }
            }
            windows {
                iconFile.set(project.file("packaging/pgpony.ico"))
                pgponyDocTypes.forEach { (mime, ext, desc) -> fileAssociation(mime, ext, desc) }
                menu = true
                menuGroup = "PGPony"
                shortcut = true
                dirChooser = true
                // Fixed identity so each new .msi upgrades the previous install in place.
                upgradeUuid = "31cd9332-799e-4963-bc22-1ebb1e9517bc"
            }
        }
    }
}

// D13 — the .deb's runtime dependencies. javax.smartcardio dlopens libpcsclite, and D7's card
// support is dead without the pcscd daemon, but Compose's linux {} block exposes no dependency
// field at all (checked against the plugin itself: debMaintainer and debPackageVersion are the
// whole deb surface). jpackage does expose one, --linux-package-deps, reached through the jpackage
// task's freeArgs.
//
// Addressed by task NAME, and through Gradle's dynamic-property API rather than by importing
// AbstractJPackageTask: that type lives in the plugin's internal package, and a build file in a
// public repo should not depend on it staying accessible. If freeArgs ever disappears this
// degrades to a no-op rather than failing the build — so `dpkg-deb -f` on the artifact is the
// check that matters, not the absence of an error here.
tasks.matching { it.name == "packageDeb" }.configureEach {
    val free = runCatching { property("freeArgs") }.getOrNull()
    if (free is ListProperty<*>) {
        @Suppress("UNCHECKED_CAST")
        // NO SPACE after the comma. jpackage is invoked as `jpackage @argfile`, and a Java
        // argfile splits on whitespace unless the value is quoted — so "pcscd, libpcsclite1"
        // arrives as three tokens and jpackage rejects `libpcsclite1` as an unknown option,
        // failing packageDeb outright. Debian's Depends field accepts a comma with no space.
        (free as ListProperty<String>).addAll("--linux-package-deps", "pcscd,libpcsclite1")
    }
}

// 1.0.1 — the Windows CLI had no console. jpackage builds a GUI-subsystem executable, and a
// GUI-subsystem process on Windows has no stdout, so every `pgpony <verb>` ran and silently
// discarded its output: a documented 1.0 feature that did nothing on one of three platforms.
// Nothing caught it because the release checklist never exercised the CLI on any OS.
//
// Compose's windows { console = true } is the WRONG fix — it makes the GUI app console-subsystem
// too, so a black window flashes up behind it. jpackage's --add-launcher builds a SECOND
// executable from its own properties file, so pgpony.exe gets win-console=true while PGPony.exe
// stays windowless. Scoped to packageMsi: win-console means nothing elsewhere, and an extra
// launcher on macOS and Linux is clutter (both already have a console).
tasks.matching { it.name == "packageMsi" }.configureEach {
    val free = runCatching { property("freeArgs") }.getOrNull()
    if (free is ListProperty<*>) {
        @Suppress("UNCHECKED_CAST")
        // The launcher is named pgpony-cli, NOT pgpony, and that is not cosmetic. Windows
        // filesystems are case-insensitive, so an added launcher called `pgpony` resolves to the
        // same file as the main GUI launcher `PGPony.exe`, and jpackage dies with
        // FileAlreadyExistsException on ...\win-msi.image\PGPony\pgpony.exe.
        //
        // This is the SECOND time case-insensitivity has broken packaging in this phase: the first
        // was packaging/pgpony.icns colliding with Resources/PGPony.icns on macOS. Any packaging
        // artifact whose name differs from "PGPony" only by case will collide.
        //
        // Forward slashes are belt-and-braces, not the fix — a Java argfile treats backslash as an
        // escape character, so a raw D:\a\... path is a hazard in principle. It was NOT the cause
        // of the failure above: jpackage located the properties file and got as far as writing the
        // launcher. Normalizing costs nothing, so it stays.
        (free as ListProperty<String>).addAll(
            "--add-launcher",
            "pgpony-cli=" + project.file("packaging/pgpony-cli.properties").absolutePath.replace('\\', '/')
        )
    }
}

// Keep the CLI's interactive stdin on `./gradlew run` (defensive: no-op if run isn't a JavaExec).
tasks.matching { it.name == "run" }.configureEach {
    (this as? JavaExec)?.standardInput = System.`in`
}

// Forward selected -D properties to the forked unit-test JVM (the PGPonyAndroid pattern —
// Gradle does not propagate command-line system properties to test JVMs). Gated harnesses:
//   -DrunInterop=true    enables the gpg/sq/iOS interop tests (vendored + GpgInteropTest)
//   -DiosSecPass=…       passphrase for the protected iOS composite secret fixture
//   -Dpgpony.gpg=…       explicit gpg binary path for the desktop gpg harness
//   -DrunNetwork=true    enables the live keyserver/WKD tests (D4) — real network traffic
tasks.withType<Test>().configureEach {
    // D7 — the DesktopCardTest and any card code path need java.smartcardio in the test JVM's
    // root module set (see the compilerOptions note above).
    jvmArgs("--add-modules=java.smartcardio")
    listOf("runInterop", "iosSecPass", "pgpony.gpg", "runNetwork").forEach { k ->
        System.getProperty(k)?.let { systemProperty(k, it) }
    }
}
