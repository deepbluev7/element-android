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

package im.vector.app.features.pin.lockscreen.crypto

import android.os.Build
import android.util.Base64
import im.vector.app.features.pin.PinCodeStore
import im.vector.app.features.pin.lockscreen.crypto.LockScreenCryptoConstants.ANDROID_KEY_STORE
import im.vector.app.features.pin.lockscreen.crypto.LockScreenCryptoConstants.LEGACY_PIN_CODE_KEY_ALIAS
import org.matrix.android.sdk.api.session.securestorage.SecureStorageService
import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.KeyStore
import javax.crypto.Cipher
import javax.inject.Inject

/**
 * Used to migrate from the old PIN code key ciphers to a more secure ones.
 */
class PinCodeMigrator @Inject constructor(
        private val pinCodeStore: PinCodeStore,
        private val secureStorageService: SecureStorageService,
) {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply {
            load(null)
        }
    }

    private val legacyKey: Key get() = keyStore.getKey(LEGACY_PIN_CODE_KEY_ALIAS, null)

    /**
     * Migrates from the old ciphers and [LEGACY_PIN_CODE_KEY_ALIAS] to the [newAlias].
     */
    suspend fun migrate(newAlias: String) {
        if (!keyStore.containsAlias(LEGACY_PIN_CODE_KEY_ALIAS)) return

        val pinCode = getDecryptedPinCode() ?: return
        val encryptedPinCode = with(ByteArrayOutputStream()) {
            secureStorageService.securelyStoreObject(pinCode, newAlias, this)
            Base64.encodeToString(this.toByteArray(), Base64.NO_WRAP)
        }
        pinCodeStore.savePinCode(encryptedPinCode)
        keyStore.deleteEntry(LEGACY_PIN_CODE_KEY_ALIAS)
    }

    fun isMigrationNeeded(): Boolean = keyStore.containsAlias(LEGACY_PIN_CODE_KEY_ALIAS)

    private suspend fun getDecryptedPinCode(): String? {
        val encryptedPinCode = pinCodeStore.getPinCode() ?: return null
        val cipher = getDecodeCipher()
        val bytes = cipher.doFinal(Base64.decode(encryptedPinCode, Base64.NO_WRAP))
        return String(bytes)
    }

    private fun getDecodeCipher(): Cipher {
        return when (Build.VERSION.SDK_INT) {
            Build.VERSION_CODES.LOLLIPOP, Build.VERSION_CODES.LOLLIPOP_MR1 -> getCipherL()
            else -> getCipherM()
        }.also { it.init(Cipher.DECRYPT_MODE, legacyKey) }
    }

    private fun getCipherL(): Cipher {
        val provider = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) "AndroidOpenSSL" else "AndroidKeyStoreBCWorkaround"
        val transformation = "RSA/ECB/PKCS1Padding"
        return Cipher.getInstance(transformation, provider)
    }

    private fun getCipherM(): Cipher {
        val transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        return Cipher.getInstance(transformation)
    }
}
