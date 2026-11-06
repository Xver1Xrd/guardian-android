package dev.guardian.app

import android.content.Context
import android.content.ContextWrapper
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.guardian.crypto.KdfParameters
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class LocalVaultTest {
    @Test fun createSaveReopenAndRecoverFromTrash() {
      runBlocking {
        val base = ApplicationProvider.getApplicationContext<Context>()
        val isolated = File(base.cacheDir, "test-${UUID.randomUUID()}")
        val context = object : ContextWrapper(base) {
            override fun getNoBackupFilesDir(): File = isolated
        }
        val password = "synthetic test password".toCharArray()
        try {
            val first = LocalVault(context)
            Log.i("GuardianTest", "create started")
            first.create(password, KdfParameters(32768, 2, 1))
            Log.i("GuardianTest", "create completed")
            val note = NoteEntry(UUID.randomUUID().toString(), "тест", "синтетические данные")
            val login = LoginEntry(UUID.randomUUID().toString(), "example.test", "tester",
                "synthetic-password", "https://example.test",
                totpUri = "otpauth://totp/Example:tester?secret=JBSWY3DPEHPK3PXP&issuer=Example")
            val loginSummary = LoginSummary(login.id, login.title, login.username, login.url, false)
            first.save(note)
            first.saveLogin(login)
            Log.i("GuardianTest", "records saved")
            first.lock()

            val second = LocalVault(context)
            Log.i("GuardianTest", "unlock started")
            second.unlock(password)
            Log.i("GuardianTest", "unlock completed")
            assertEquals(listOf(note), second.list())
            assertEquals(listOf(loginSummary), second.listLogins())
            assertEquals(login, second.loadLogin(login.id))
            second.save(note.copy(deleted = true))
            assertEquals(true, second.list().single().deleted)
            second.save(note)
            assertEquals(listOf(note), second.list())
            assertEquals(listOf(loginSummary), second.listLogins())
            second.lock()
            Log.i("GuardianTest", "test completed")
        } finally {
            password.fill('\u0000')
            isolated.deleteRecursively()
        }
      }
    }
}
