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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import im.vector.app.features.pin.lockscreen.crypto.LockScreenCryptoConstants.ANDROID_KEY_STORE
import java.security.Key
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Used to create, get and check validity of the system/biometric key.
 */
class SystemKeyHelper private constructor(
        val alias: String,
) {

    companion object {
        fun create(alias: String): SystemKeyHelper = SystemKeyHelper(alias)
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
    }

    /**
     * Makes sure the system key is created, either by getting it from the [KeyStore] or by creating and storing a new instance.
     * @return The system key.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun ensureKey(): SecretKey {
        val secretKeyEntry = (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (secretKeyEntry == null || !checkKeyValidation(secretKeyEntry)) {
            // Delete last key in case it was invalidated
            keyStore.deleteEntry(alias)
            // Create new key
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            val keyGenSpec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(128)
                    .setUserAuthenticationRequired(true)
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            setInvalidatedByBiometricEnrollment(true)
                        }
                    }
                    .build()
            generator.init(keyGenSpec)
            return generator.generateKey()
        }
        return secretKeyEntry
    }

    /**
     * Creates and initializes a [Cipher] to make sure it's valid.
     * @throws KeyPermanentlyInvalidatedException if the key has been invalidated.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    @Throws(KeyPermanentlyInvalidatedException::class)
    fun initializeKeyOrThrow(key: Key) {
        Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, key)
    }

    /**
     * Checks if the exists in the [KeyStore] and is valid.
     */
    fun hasValidKey(): Boolean {
        return keyStore.containsAlias(alias) && checkKeyValidation(keyStore.getKey(alias, null))
    }

    private fun checkKeyValidation(key: Key): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                initializeKeyOrThrow(key)
            } catch (e: KeyPermanentlyInvalidatedException) {
                return false
            }
        }
        return true
    }
}
