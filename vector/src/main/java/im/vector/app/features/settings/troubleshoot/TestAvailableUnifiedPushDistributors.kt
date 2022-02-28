/*
 * Copyright (c) 2022 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package im.vector.app.features.settings.troubleshoot

import android.content.Intent
import androidx.activity.result.ActivityResultLauncher
import androidx.fragment.app.FragmentActivity
import im.vector.app.R
import im.vector.app.core.pushers.UnifiedPushHelper
import im.vector.app.core.resources.StringProvider
import im.vector.app.push.fcm.FcmHelper
import javax.inject.Inject

class TestAvailableUnifiedPushDistributors @Inject constructor(private val context: FragmentActivity,
                                                    private val stringProvider: StringProvider) :
        TroubleshootTest(R.string.settings_troubleshoot_test_distributors_title) {

    override fun perform(activityResultLauncher: ActivityResultLauncher<Intent>) {
        val distributors = UnifiedPushHelper.getExternalDistributors(context)
        if (distributors.isEmpty()) {
            description = if (FcmHelper.isPushSupported()) {
                stringProvider.getString(R.string.settings_troubleshoot_test_distributors_gplay)
            } else {
                stringProvider.getString(R.string.settings_troubleshoot_test_distributors_fdroid)
            }
            status = TestStatus.SUCCESS
        } else {
            description = stringProvider.getString(R.string.settings_troubleshoot_test_distributors_many,
                    distributors.size + 1)
            status = TestStatus.SUCCESS
        }
    }
}