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

import android.support.annotation.MainThread

/**
 * Observer for receiving update results from asynchronous
 * [CertStore.update] method.
 *
 * Callbacks are executed on the main thread.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 *
 * @since 0.9.0
 */
interface UpdateObserver {

    /**
     * Called when an update has been started and [UpdateType] has been evaluated.
     *
     * @param type Type of updated that was selected based on the input parameters and stored data.
     */
    @MainThread
    fun onUpdateStarted(type: UpdateType)

    /**
     * Called when an update finishes.
     *
     * In case of [UpdateType.NO_UPDATE], it's called immediately after [onUpdateStarted].
     *
     * @param result Result of the update.
     */
    @MainThread
    fun onUpdateFinished(result: UpdateResult)
}