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

package com.wultra.android.sslpinning

/**
 * Type of update initiated by [CertStore.update] method.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 *
 * @since 0.9.0
 */
enum class UpdateType {

    /**
     * The update is direct.
     *
     * App should wait for the update to finish because it means there is some serious problem
     * with current fingerprint data. Network requests (SSL handshakes) might fail.
     */
    DIRECT,

    /**
     * The update is silent.
     *
     * App can continue normally. But it's time to check for updates.
     * It's improbable that network requests (SSL handshakes)
     * would fail since the local fingerprint data are still valid.
     *
     * Note that even though the local data are valid, there might be some remote changes
     * (changed server certificate) and network requests (SSL handshakes) might still fail.
     */
    SILENT,

    /**
     * No update is performed.
     *
     * App con continue normally.
     * There's no need to perform update based on the locally stored fingerprints.
     *
     * Note that even though the local data are valid, there might be some remote changes
     * (changed server certificate) and network requests (SSL handshakes) might still fail.
     */
    NO_UPDATE;

    /**
     * Check if this type of update is actually performing update.
     */
    val isPerformingUpdate: Boolean
    get() {
        return this != NO_UPDATE
    }
}