import com.android.build.api.dsl.DefaultConfig
import com.android.build.gradle.BaseExtension
import java.io.FileInputStream
import java.util.Properties
import java.util.regex.Pattern

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

val currentFlavor = currentFlavor()

ext {

    // overriding artifact ID for the basic flavor. This is needed when the artifact is being published
    when (currentFlavor) {
        "basic" -> project.setProperty("ARTIFACT_ID", "wultra-ssl-pinning")
    }

    // set the flavor name for the
    extra.set("flavor", currentFlavor)
}

android {
    namespace = "com.wultra.android.sslpinning"
    testNamespace = "com.wultra.android.sslpinning.test"
    compileSdk = Constants.Android.compileSdkVersion
    flavorDimensionList += "scope"

    defaultConfig {
        minSdk = Constants.Android.minSdkVersion
        @Suppress("DEPRECATION")
        targetSdk = Constants.Android.targetSdkVersion

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"
        loadInstrumentationTestConfigProperties(project, this)
    }


    productFlavors {

        create("basic") {
            dimension = "scope"
        }

        create("powerauth") {
            dimension = "scope"
        }
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
    }

    // avoids a gradle warning, otherwise unused due to custom config in android-release-aar.gradle
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }

    lint {
        // to handle warning coming from a transitive dependency
        // - obsolete 'androidx.fragment' through 'powerauth-sdk'
        disable.add("ObsoleteLintCustomCheck")
    }

    // Make ktlint run before build
    tasks.matching { it.name.startsWith("preBuild") }.forEach {

        it.doFirst {
            logger.lifecycle("\n# Building the ${currentFlavor.uppercase()} version of the library")
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:${Constants.BuildScript.kotlinVersion}")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("androidx.annotation:annotation:1.7.1")
    implementation("androidx.security:security-crypto:1.0.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.13.5")
    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")

    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("com.squareup.okhttp3:okhttp:4.10.0")

    // PowerAuth dependencies are only needed for the full implementation.
    // Note that the "add" method cannot be used because maven publish does
    // not include the dependency in the pom file (add("powerauthCompileOnly", "com.wultra.android.powerauth:powerauth-sdk:1.9.3"))
    if (currentFlavor == "powerauth") {
        androidTestImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
        testImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
        testImplementation("io.getlime.security:powerauth-java-crypto:1.4.0")
        compileOnly("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
    }

    constraints {
        implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:${Constants.BuildScript.kotlinVersion}") {
            because("Avoids conflicts with 'kotlin-stdlib'")
        }
    }
}

apply("android-release-aar.gradle")

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
        "test.sslPinning.appName"
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

fun Project.currentFlavor(): String {
    val paramStr = gradle.startParameter.taskRequests.toString().lowercase()

    // make sure to support commands like "assembleBasic" or just "assemble"
    val buildTypePattern =
        if (paramStr.contains("release") || paramStr.contains("debug")) {
            "(release|debug)"
        } else {
            ""
        }
    val pattern: Pattern = Pattern.compile("(bundle|assemble)(\\w+)$buildTypePattern")

    val matcher = pattern.matcher(paramStr)
    val flavor =
        if (matcher.find()) {
            when (val fl = matcher.group(2).lowercase()) {
                "basic" -> "basic"
                "powerauth" -> "powerauth"
                else -> {
                    logger.lifecycle("Unknown flavor selected: '$fl', defaulting to \"powerauth\"")
                    "powerauth" // backup value
                }
            }
        } else {
            logger.warn("Failed to find the current flavor, using the \"powerauth\" flavor")
            "powerauth"
        }
    return flavor
}