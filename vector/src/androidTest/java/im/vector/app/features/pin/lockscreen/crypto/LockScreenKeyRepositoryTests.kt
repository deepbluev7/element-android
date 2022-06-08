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

import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import im.vector.app.features.settings.VectorPreferences
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.spyk
import io.mockk.verify
import org.amshove.kluent.shouldBeFalse
import org.amshove.kluent.shouldBeTrue
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.matrix.android.sdk.api.session.securestorage.SecureStorageService
import java.security.KeyStore
import javax.inject.Inject

@HiltAndroidTest
class LockScreenKeyRepositoryTests {

    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var secureStorageService: SecureStorageService

    private lateinit var lockScreenKeyRepository: LockScreenKeyRepository
    private val pinCodeMigrator: PinCodeMigrator = mockk(relaxed = true)
    private lateinit var spySecureStorageService: SecureStorageService
    private val vectorPreferences: VectorPreferences = mockk(relaxed = true)
    private lateinit var systemKeyHelper: SystemKeyHelper

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(LockScreenCryptoConstants.ANDROID_KEY_STORE).also { it.load(null) }
    }

    @Before
    fun setup() {
        hiltRule.inject()

        spySecureStorageService = spyk(secureStorageService)

        systemKeyHelper = spyk(SystemKeyHelper.create("base.system")) {
            every { initializeKeyOrThrow(any()) } returns Unit
        }
        mockkObject(SystemKeyHelper.Companion)
        every { SystemKeyHelper.create(any()) } returns systemKeyHelper
        lockScreenKeyRepository = LockScreenKeyRepository("base", pinCodeMigrator, spySecureStorageService, vectorPreferences)
    }

    @After
    fun tearDown() {
        clearAllMocks()
        keyStore.deleteEntry("base.pin_code")
        keyStore.deleteEntry("base.system")
    }

    @Test
    fun gettingSystemKeyAlsoInitializesIt() {
        every { systemKeyHelper.ensureKey() } returns mockk()
        every { systemKeyHelper.initializeKeyOrThrow(any()) } returns Unit

        lockScreenKeyRepository.ensureSystemKey()

        verify { systemKeyHelper.initializeKeyOrThrow(any()) }
    }

    @Test
    fun ensureSystemKeyCreatesSystemKeyIfNeeded() {
        lockScreenKeyRepository.ensureSystemKey()
        lockScreenKeyRepository.hasSystemKey().shouldBeTrue()
    }

    @Test
    fun encryptPinCodeCreatesPinCodeKey() {
        lockScreenKeyRepository.encryptPinCode("1234")
        lockScreenKeyRepository.hasPinCodeKey().shouldBeTrue()
    }

    @Test
    fun isSystemKeyValidReturnsWhatSystemKeyHelperHasValidKeyReplies() {
        every { systemKeyHelper.initializeKeyOrThrow(any()) } returns Unit

        // Key needs to exist to be check validity
        lockScreenKeyRepository.ensureSystemKey()

        every { systemKeyHelper.hasValidKey() } returns false
        lockScreenKeyRepository.isSystemKeyValid().shouldBeFalse()

        every { systemKeyHelper.hasValidKey() } returns true
        lockScreenKeyRepository.isSystemKeyValid().shouldBeTrue()
    }

    @Test
    fun hasSystemKeyReturnsTrueAfterSystemKeyIsCreated() {
        lockScreenKeyRepository.hasSystemKey().shouldBeFalse()

        lockScreenKeyRepository.ensureSystemKey()

        lockScreenKeyRepository.hasSystemKey().shouldBeTrue()
    }

    @Test
    fun hasPinCodeKeyReturnsTrueAfterPinCodeKeyIsCreated() {
        lockScreenKeyRepository.hasPinCodeKey().shouldBeFalse()

        lockScreenKeyRepository.encryptPinCode("1234")

        lockScreenKeyRepository.hasPinCodeKey().shouldBeTrue()
    }

    @Test
    fun deleteSystemKeyRemovesTheKeyFromKeyStore() {
        lockScreenKeyRepository.ensureSystemKey()
        lockScreenKeyRepository.hasSystemKey().shouldBeTrue()

        lockScreenKeyRepository.deleteSystemKey()

        lockScreenKeyRepository.hasSystemKey().shouldBeFalse()
    }

    @Test
    fun deletePinCodeKeyRemovesTheKeyFromKeyStore() {
        lockScreenKeyRepository.encryptPinCode("1234")
        lockScreenKeyRepository.hasPinCodeKey().shouldBeTrue()

        lockScreenKeyRepository.deletePinCodeKey()

        lockScreenKeyRepository.hasPinCodeKey().shouldBeFalse()
    }
}
