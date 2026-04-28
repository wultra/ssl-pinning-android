import com.android.build.api.dsl.DefaultConfig
import com.android.build.gradle.BaseExtension
import java.io.FileInputStream
import java.util.Properties

/*
 * Copyright 2018 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
}

apply<com.wultra.plugin.WultraAndroidReleasePlugin>()

android {
    namespace = "com.wultra.android.sslpinning"
    testNamespace = "com.wultra.android.sslpinning.test"
    compileSdk = Constants.Android.compileSdkVersion

    defaultConfig {
        minSdk = Constants.Android.minSdkVersion

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"
        // Network tests (CertStoreNetworkTest) require additional arguments:
        //   test.sslPinning.adminLogin, test.sslPinning.adminPassword, test.sslPinning.urlToPin
        loadInstrumentationTestConfigProperties(project, this)
    }

    buildTypes {
        debug {
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
        }
        release {
            isMinifyEnabled = false
            consumerProguardFiles("proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = Constants.Java.sourceCompatibility
        targetCompatibility = Constants.Java.targetCompatibility
    }

    kotlinOptions {
        jvmTarget = Constants.Java.kotlinJvmTarget
        suppressWarnings = false
    }

    lint {
        // to handle warning coming from a transitive dependency
        // - obsolete 'androidx.fragment' through 'powerauth-sdk'
        disable.add("ObsoleteLintCustomCheck")
    }
}

dependencies {
    compileOnly("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")

    implementation("org.jetbrains.kotlin:kotlin-stdlib:${Constants.BuildScript.kotlinVersion}")
    implementation("com.google.code.gson:gson:2.13.2")
    implementation("androidx.annotation:annotation:1.10.0")
    implementation("androidx.security:security-crypto:1.1.0")

    testImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.14.9")
    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")
    testImplementation("io.getlime.security:powerauth-java-crypto:1.10.0")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
    androidTestImplementation("com.squareup.okhttp3:okhttp:5.3.2")

    constraints {
        implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:${Constants.BuildScript.kotlinVersion}") {
            because("Avoids conflicts with 'kotlin-stdlib'")
        }
    }
}

// The Wultra release plugin registers an `androidJavadocs` Javadoc task that excludes *.kt files.
// Since this library is Kotlin-only there are no Java sources to document, so we suppress the
// "no public classes found" error. The plugin also picks up a `dokkaJavadoc` task (when present)
// to include Kotlin API docs in the -javadoc.jar; we register one here pointing at Dokka's HTML
// output so the published artifact contains meaningful documentation.
tasks.withType<Javadoc>().configureEach {
    isFailOnError = false
}

// Load properties for instrumentation tests.
fun loadInstrumentationTestConfigProperties(project: Project, defaultConfig: DefaultConfig) {
    val configsRoot = File("${project.rootProject.projectDir}/configs")
    val defaultConfigFile = File(configsRoot, "integration-tests.properties")
    val privateConfigFile = File(configsRoot, "private-integration-tests.properties")
    val configPropertiesFile = if (privateConfigFile.canRead()) {
        privateConfigFile
    } else {
        defaultConfigFile
    }
    val instrumentationArguments = arrayOf(
        "test.sslPinning.baseUrl",
        "test.sslPinning.appName",
        "test.sslPinning.adminLogin",
        "test.sslPinning.adminPassword",
        "test.sslPinning.urlToPin",
    )

    project.logger.info("LOADING_PROPERTIES Reading $configPropertiesFile")
    if (configPropertiesFile.canRead()) {
        val props = Properties()
        props.load(FileInputStream(configPropertiesFile))

        for (key in instrumentationArguments) {
            defaultConfig.testInstrumentationRunnerArguments[key] = "${props[key]}"
        }
    } else {
        project.logger.warn("Loading properties error: Missing $configPropertiesFile")
    }
}