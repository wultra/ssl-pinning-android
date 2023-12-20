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
    id("com.wultra.android.sslpinning.test")
}

android {
    namespace = "com.wultra.android.sslpinning"
    testNamespace = "com.wultra.android.sslpinning.test"
    compileSdk = Constants.Android.compileSdkVersion

    defaultConfig {
        minSdk = Constants.Android.minSdkVersion
        @Suppress("DEPRECATION")
        targetSdk = Constants.Android.targetSdkVersion

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments["clearPackageData"] = "true"
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
}

dependencies {
    compileOnly("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")

    implementation("org.jetbrains.kotlin:kotlin-stdlib:${Constants.BuildScript.kotlinVersion}")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("androidx.annotation:annotation:1.7.1")

    testImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.13.5")
    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")
    testImplementation("io.getlime.security:powerauth-java-crypto:1.4.0")

    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("com.wultra.android.powerauth:powerauth-sdk:${Constants.Dependencies.powerAuthSdkVersion}")
    androidTestImplementation("com.squareup.okhttp3:okhttp:4.10.0")

    constraints {
        implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:${Constants.BuildScript.kotlinVersion}") {
            because("Avoids conflicts with 'kotlin-stdlib'")
        }
    }
}

apply("android-release-aar.gradle")