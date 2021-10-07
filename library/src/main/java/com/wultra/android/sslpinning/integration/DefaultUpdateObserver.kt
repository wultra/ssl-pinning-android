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

package com.wultra.android.sslpinning.integration

import androidx.annotation.MainThread
import com.wultra.android.sslpinning.UpdateObserver
import com.wultra.android.sslpinning.UpdateResult
import com.wultra.android.sslpinning.UpdateType

/**
 * Utility [UpdateObserver] that simplifies integration of CertStore updates.
 *
 * It continues execution that's supposed to happen after successful
 * [com.wultra.android.sslpinning.CertStore] update.
 * @author Tomas Kypta, tomas.kypta@wultra.com
 *
 * @since 0.9.0
 */
abstract class DefaultUpdateObserver : UpdateObserver {

    override fun onUpdateStarted(type: UpdateType) {
        when (type) {
            UpdateType.NO_UPDATE,
            UpdateType.SILENT ->
                continueExecution()
            else -> {}
        }
    }

    override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
        if (result == UpdateResult.OK) {
            if (type == UpdateType.DIRECT) {
                continueExecution()
            }
        } else {
            handleFailedUpdate(type, result)
        }
    }

    /**
     * Method to contain code that's supposed to run after successful CertStore update.
     *
     * The method is invoked when it's safe to continue with the execution.
     * That means after finished [UpdateType.DIRECT] or after started
     * [UpdateType.SILENT], [UpdateType.NO_UPDATE].
     *
     * The method is called on the main thread.
     */
    @MainThread
    abstract fun continueExecution()

    /**
     * Common handling of failed update (not [UpdateResult.OK]).
     *
     * The method is called on the main thread.
     *
     * @param type Type of update
     * @param result Result of the update.
     */
    @MainThread
    open fun handleFailedUpdate(type: UpdateType, result: UpdateResult) {}
}