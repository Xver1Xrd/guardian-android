package dev.guardian.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Version 1 uses Argon2id to wrap a random 256-bit DEK. All byte arrays are copied at boundaries. */
data class KdfParameters(val memoryKiB: Int = 65536, val iterations: Int = 3, val parallelism: Int = 1) {
    init {
        require(memoryKiB in 32768..1048576 && iterations in 2..20 && parallelism in 1..8)
    }
}

class VaultHeader internal constructor(
    val version: Int,
    salt: ByteArray,
    val kdf: KdfParameters,
    nonce: ByteArray,
    wrappedKey: ByteArray,
) {
    val salt = salt.clone()
    val nonce = nonce.clone()
    val wrappedKey = wrappedKey.clone()
}

class CipherRecord internal constructor(
    val version: Int,
    val id: String,
    val kind: String,
    nonce: ByteArray,
    ciphertext: ByteArray,
) {
    val nonce = nonce.clone()
    val ciphertext = ciphertext.clone()
}

class VaultKey internal constructor(key: ByteArray) : AutoCloseable {
    private var bytes: ByteArray? = key.clone()
    internal fun withBytes(block: (ByteArray) -> Unit) = synchronized(this) {
        val live = bytes ?: error("Vault key is closed")
        block(live)
    }
    override fun close() = synchronized(this) { bytes?.fill(0); bytes = null }
}

object VaultCrypto {
    private const val VERSION = 1
    private val random = SecureRandom()

    fun create(password: CharArray, params: KdfParameters = KdfParameters()): Pair<VaultHeader, VaultKey> {
        require(password.isNotEmpty())
        val salt = randomBytes(32)
        val dek = randomBytes(32)
        val kek = derive(password, salt, params)
        try {
            val nonce = randomBytes(12)
            val header = VaultHeader(VERSION, salt, params, nonce,
                encrypt(kek, nonce, headerAad(VERSION, salt, params), dek))
            return header to VaultKey(dek)
        } finally {
            kek.fill(0)
            dek.fill(0)
        }
    }

    /** An invalid password and a damaged wrapped key both fail AEAD authentication. */
    fun unlock(header: VaultHeader, password: CharArray): VaultKey {
        validate(header)
        val kek = derive(password, header.salt, header.kdf)
        try {
            val dek = decrypt(kek, header.nonce, headerAad(header.version, header.salt, header.kdf), header.wrappedKey)
            try {
                require(dek.size == 32) { "Invalid DEK length" }
                return VaultKey(dek)
            } finally { dek.fill(0) }
        } finally { kek.fill(0) }
    }

    fun changePassword(header: VaultHeader, oldPassword: CharArray, newPassword: CharArray,
                       newParams: KdfParameters = header.kdf): VaultHeader {
        require(newPassword.isNotEmpty())
        unlock(header, oldPassword).use { key ->
            val salt = randomBytes(32)
            val nonce = randomBytes(12)
            val kek = derive(newPassword, salt, newParams)
            try {
                var result: VaultHeader? = null
                key.withBytes { dek -> result = VaultHeader(VERSION, salt, newParams, nonce,
                    encrypt(kek, nonce, headerAad(VERSION, salt, newParams), dek)) }
                return result!!
            } finally { kek.fill(0) }
        }
    }

    fun encryptRecord(key: VaultKey, id: String, kind: String, plaintext: ByteArray): CipherRecord {
        require(id.isNotBlank() && kind.isNotBlank() && id.length <= 256 && kind.length <= 64)
        val nonce = randomBytes(12)
        var result: CipherRecord? = null
        key.withBytes { dek -> result = CipherRecord(VERSION, id, kind, nonce,
            encrypt(dek, nonce, recordAad(VERSION, id, kind), plaintext)) }
        return result!!
    }

    fun decryptRecord(key: VaultKey, record: CipherRecord): ByteArray {
        require(record.version == VERSION && record.nonce.size == 12 && record.ciphertext.size >= 16)
        var result: ByteArray? = null
        key.withBytes { dek -> result = decrypt(dek, record.nonce,
            recordAad(record.version, record.id, record.kind), record.ciphertext) }
        return result!!
    }

    private fun validate(header: VaultHeader) {
        require(header.version == VERSION && header.salt.size == 32 && header.nonce.size == 12 &&
            header.wrappedKey.size == 48) { "Unsupported or malformed vault header" }
    }

    private fun derive(password: CharArray, salt: ByteArray, params: KdfParameters): ByteArray {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        val encoded = encoder.encode(CharBuffer.wrap(password))
        val passBytes = ByteArray(encoded.remaining())
        encoded.get(passBytes)
        if (encoded.hasArray()) Arrays.fill(encoded.array(), 0)
        val derived = ByteArray(32)
        try {
            val spec = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt).withMemoryAsKB(params.memoryKiB)
                .withIterations(params.iterations).withParallelism(params.parallelism).build()
            Argon2BytesGenerator().apply { init(spec) }.generateBytes(passBytes, derived)
            return derived
        } finally { passBytes.fill(0) }
    }

    private fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(data)
        }

    private fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(data)
        }

    private fun headerAad(version: Int, salt: ByteArray, p: KdfParameters): ByteArray =
        ByteBuffer.allocate(8 + 4 * 4 + salt.size).put("GUARDIAN".toByteArray()).putInt(version)
            .putInt(p.memoryKiB).putInt(p.iterations).putInt(p.parallelism).put(salt).array()

    private fun recordAad(version: Int, id: String, kind: String): ByteArray {
        val idBytes = id.toByteArray(StandardCharsets.UTF_8)
        val kindBytes = kind.toByteArray(StandardCharsets.UTF_8)
        return ByteBuffer.allocate(4 + 4 + idBytes.size + 4 + kindBytes.size)
            .putInt(version).putInt(idBytes.size).put(idBytes).putInt(kindBytes.size).put(kindBytes).array()
    }

    private fun randomBytes(size: Int) = ByteArray(size).also(random::nextBytes)
}
