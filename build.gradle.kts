plugins {
    kotlin("jvm") version "2.4.20" apply false
    id("com.android.application") version "9.4.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}

allprojects {
    group = "dev.altru.radialterminal"
    version = "0.2.0-SNAPSHOT"

    repositories {
        google()
        mavenCentral()
    }
}
