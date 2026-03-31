/*
 * Copyright 2026 Wultra s.r.o.
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

package com.wultra.android.sslpinning.model

/**
 * The [DomainsConfig] class holds domain-specific SSL pinning configuration
 * received from the server.
 *
 * When present, it can selectively bypass SSL pinning for specific domains or
 * for all domains not explicitly listed.
 *
 * @property sslPinningRequiredForUnlisted Whether SSL pinning is required for domains
 *           not explicitly listed in [domains].
 * @property domains Domain-specific SSL pinning configuration entries.
 */
internal data class DomainsConfig(
    val sslPinningRequiredForUnlisted: Boolean,
    val domains: List<DomainConfig>
) {
    /**
     * Returns whether SSL pinning is required for the given domain name.
     *
     * If the domain is listed, returns its [DomainConfig.sslPinningRequired] value.
     * Otherwise, falls back to [sslPinningRequiredForUnlisted].
     *
     * @param domain The domain name to check.
     * @return `true` if SSL pinning is required for the domain, `false` otherwise.
     */
    fun isPinningRequired(domain: String): Boolean {
        val config = domains.firstOrNull { it.name == domain }
        return config?.sslPinningRequired ?: sslPinningRequiredForUnlisted
    }
}

/**
 * The [DomainConfig] class holds SSL pinning configuration for a specific domain.
 *
 * @property name The domain name.
 * @property sslPinningRequired Whether SSL pinning is required for this domain.
 */
internal data class DomainConfig(
    val name: String,
    val sslPinningRequired: Boolean
)
