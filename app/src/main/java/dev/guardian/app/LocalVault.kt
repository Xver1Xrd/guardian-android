package dev.guardian.app

import android.content.Context
import android.util.AtomicFile
import dev.guardian.crypto.CipherRecord
import dev.guardian.crypto.VaultCodec
import dev.guardian.crypto.VaultCrypto
import dev.guardian.crypto.VaultKey
import dev.guardian.crypto.KdfParameters
import dev.guardian.authenticator.TotpUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

internal data class NoteEntry(val id: String, val title: String, val body: String, val deleted: Boolean = false)
internal data class LoginEntry(
    val id: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val deleted: Boolean = false,
    val totpUri: String = "",
)
internal data class LoginSummary(
    val id: String,
    val title: String,
    val username: String,
    val url: String,
    val deleted: Boolean,
)

/** Local-only encrypted note store. Filenames are random IDs; note titles and bodies are encrypted. */
internal class LocalVault(context: Context) {
    private val root = File(context.noBackupFilesDir, "vault-v1")
    private val headerFile = File(root, "header.bin")
    private var key: VaultKey? = null

    val exists: Boolean get() = headerFile.exists()
    val unlocked: Boolean get() = key != null

    suspend fun create(password: CharArray, params: KdfParameters = KdfParameters()) = withContext(Dispatchers.IO) {
        check(!exists) { "Хранилище уже существует" }
        root.mkdirs()
        val (header, newKey) = VaultCrypto.create(password, params)
        try {
            atomicWrite(headerFile, VaultCodec.encodeHeader(header))
            key = newKey
        } catch (error: Exception) {
            newKey.close()
            throw error
        }
    }

    suspend fun unlock(password: CharArray) = withContext(Dispatchers.IO) {
        check(key == null)
        key = VaultCrypto.unlock(VaultCodec.decodeHeader(atomicRead(headerFile, 256)), password)
    }

    fun lock() { key?.close(); key = null }

    suspend fun list(): List<NoteEntry> = withContext(Dispatchers.IO) {
        val live = checkNotNull(key) { "Хранилище заблокировано" }
        root.listFiles { file -> file.name.endsWith(".rec") }?.mapNotNull { file ->
            val record = VaultCodec.decodeRecord(atomicRead(file, 16 * 1024 * 1024 + 512))
            check(file.name == "${record.id}.rec")
            check(record.kind == "note" || record.kind == "login")
            if (record.kind != "note") return@mapNotNull null
            val plaintext = VaultCrypto.decryptRecord(live, record)
            try {
                val json = JSONObject(String(plaintext, Charsets.UTF_8))
                NoteEntry(record.id, json.getString("title"), json.getString("body"), json.optBoolean("deleted"))
            } finally { plaintext.fill(0) }
        }?.sortedBy { it.title.lowercase() } ?: emptyList()
    }

    suspend fun listLogins(): List<LoginSummary> = withContext(Dispatchers.IO) {
        val live = checkNotNull(key) { "Хранилище заблокировано" }
        root.listFiles { file -> file.name.endsWith(".rec") }?.mapNotNull { file ->
            val record = VaultCodec.decodeRecord(atomicRead(file, 16 * 1024 * 1024 + 512))
            check(file.name == "${record.id}.rec")
            check(record.kind == "note" || record.kind == "login")
            if (record.kind != "login") return@mapNotNull null
            val plaintext = VaultCrypto.decryptRecord(live, record)
            try {
                val json = JSONObject(String(plaintext, Charsets.UTF_8))
                LoginSummary(record.id, json.getString("title"), json.getString("username"),
                    json.getString("url"), json.optBoolean("deleted"))
            } finally { plaintext.fill(0) }
        }?.sortedBy { it.title.lowercase() } ?: emptyList()
    }

    suspend fun loadLogin(id: String): LoginEntry = withContext(Dispatchers.IO) {
        require(UUID.fromString(id).toString() == id)
        val live = checkNotNull(key) { "Хранилище заблокировано" }
        val record = VaultCodec.decodeRecord(atomicRead(File(root, "$id.rec"), 16 * 1024 * 1024 + 512))
        check(record.id == id && record.kind == "login")
        val plaintext = VaultCrypto.decryptRecord(live, record)
        try {
            val json = JSONObject(String(plaintext, Charsets.UTF_8))
            LoginEntry(id, json.getString("title"), json.getString("username"),
                json.getString("password"), json.getString("url"), json.optBoolean("deleted"),
                json.optString("totpUri", ""))
        } finally { plaintext.fill(0) }
    }

    suspend fun save(note: NoteEntry) = withContext(Dispatchers.IO) {
        val live = checkNotNull(key) { "Хранилище заблокировано" }
        require(UUID.fromString(note.id).toString() == note.id)
        require(note.title.length <= 512 && note.body.length <= 1_000_000)
        val plaintext = JSONObject().put("title", note.title).put("body", note.body)
            .put("deleted", note.deleted).toString().toByteArray(Charsets.UTF_8)
        try {
            val encrypted: CipherRecord = VaultCrypto.encryptRecord(live, note.id, "note", plaintext)
            writeRecord(note.id, "note", encrypted)
        } finally { plaintext.fill(0) }
    }

    suspend fun saveLogin(login: LoginEntry) = withContext(Dispatchers.IO) {
        val live = checkNotNull(key) { "Хранилище заблокировано" }
        require(UUID.fromString(login.id).toString() == login.id)
        require(login.title.length <= 512 && login.username.length <= 512 &&
            login.password.length <= 8192 && login.url.length <= 4096 && login.totpUri.length <= 8192)
        if (login.totpUri.isNotBlank()) TotpUri.parse(login.totpUri).close()
        val plaintext = JSONObject().put("title", login.title).put("username", login.username)
            .put("password", login.password).put("url", login.url).put("deleted", login.deleted)
            .put("totpUri", login.totpUri)
            .toString().toByteArray(Charsets.UTF_8)
        try {
            val encrypted = VaultCrypto.encryptRecord(live, login.id, "login", plaintext)
            writeRecord(login.id, "login", encrypted)
        } finally { plaintext.fill(0) }
    }

    private fun writeRecord(id: String, kind: String, encrypted: CipherRecord) {
        val file = File(root, "$id.rec")
        if (file.exists()) {
            val previous = VaultCodec.decodeRecord(atomicRead(file, 16 * 1024 * 1024 + 512))
            check(previous.id == id && previous.kind == kind) { "Record identity mismatch" }
        }
        atomicWrite(file, VaultCodec.encodeRecord(encrypted))
    }

    private fun atomicWrite(file: File, bytes: ByteArray) {
        val target = AtomicFile(file)
        val stream = target.startWrite()
        try {
            stream.write(bytes)
            target.finishWrite(stream)
        } catch (error: Exception) {
            target.failWrite(stream)
            throw error
        }
    }

    private fun atomicRead(file: File, maxBytes: Int): ByteArray = AtomicFile(file).openRead().use { stream ->
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            require(output.size() + count <= maxBytes) { "Oversized encrypted file" }
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }
}
