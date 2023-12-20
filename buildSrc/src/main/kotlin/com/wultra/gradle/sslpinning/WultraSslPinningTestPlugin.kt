/*
 * Copyright 2023 Wultra s.r.o.
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

package com.wultra.gradle.sslpinning

import com.android.build.gradle.BaseExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.getByType

/**
 * Plugin for handling server configurations for instrumentation tests.
 */
class WultraSslPinningTestPlugin : Plugin<Project> {

    override fun apply(target: Project) {
        target.loadPropertiesFromGradleProps()
        target.addInstrumentationArgumentsToDefaultConfig()
    }

    private val instrumentationArgumentKeys = setOf("test.sslPinning.baseUrl", "test.sslPinning.appName")
    private val instrumentationArguments = mutableMapOf<String, String>()

    private fun Project.loadPropertiesFromGradleProps() {
        for (key in instrumentationArgumentKeys) {
            project.properties[key]?.let {
                instrumentationArguments[key] = it.toString()
            }
        }
    }

    private fun Project.addInstrumentationArgumentsToDefaultConfig() {
        project.extensions.getByType<BaseExtension>().let {
            it.defaultConfig {
                for (entry in instrumentationArguments) {
                    this.testInstrumentationRunnerArguments[entry.key] = entry.value
                }
            }
        }
    }
}