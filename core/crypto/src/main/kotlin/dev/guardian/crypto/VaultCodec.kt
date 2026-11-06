package dev.guardian.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

/** Strict, length-bounded binary encoding. Plaintext entry fields must remain inside CipherRecord.ciphertext. */
object VaultCodec {
    private const val HEADER_MAGIC = 0x47564831 // GVH1
    private const val RECORD_MAGIC = 0x47565231 // GVR1
    private const val MAX_RECORD = 16 * 1024 * 1024

    fun encodeHeader(header: VaultHeader): ByteArray = write {
        writeInt(HEADER_MAGIC)
        writeInt(header.version)
        writeInt(header.kdf.memoryKiB)
        writeInt(header.kdf.iterations)
        writeInt(header.kdf.parallelism)
        writeBytes(header.salt)
        writeBytes(header.nonce)
        writeBytes(header.wrappedKey)
    }

    fun decodeHeader(bytes: ByteArray): VaultHeader = read(bytes, 256) {
        require(readInt() == HEADER_MAGIC)
        val version = readInt()
        require(version == 1) { "Unsupported vault version" }
        val kdf = KdfParameters(readInt(), readInt(), readInt())
        VaultHeader(version, readBytes(32, 32), kdf, readBytes(12, 12), readBytes(48, 48))
    }

    fun encodeRecord(record: CipherRecord): ByteArray = write {
        writeInt(RECORD_MAGIC)
        writeInt(record.version)
        writeUtf8(record.id)
        writeUtf8(record.kind)
        writeBytes(record.nonce)
        writeBytes(record.ciphertext)
    }

    fun decodeRecord(bytes: ByteArray): CipherRecord = read(bytes, MAX_RECORD + 512) {
        require(readInt() == RECORD_MAGIC)
        val version = readInt()
        require(version == 1) { "Unsupported record version" }
        CipherRecord(version, readUtf8(256), readUtf8(64), readBytes(12, 12), readBytes(16, MAX_RECORD))
    }

    private fun write(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { output ->
            DataOutputStream(output).use(block)
            output.toByteArray()
        }

    private fun <T> read(bytes: ByteArray, maxSize: Int, block: DataInputStream.() -> T): T {
        require(bytes.size <= maxSize)
        return DataInputStream(ByteArrayInputStream(bytes)).use { stream ->
            val value = stream.block()
            require(stream.available() == 0) { "Trailing data" }
            value
        }
    }

    private fun DataOutputStream.writeBytes(bytes: ByteArray) {
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataInputStream.readBytes(min: Int, max: Int): ByteArray {
        val length = readInt()
        require(length in min..max)
        return ByteArray(length).also { readFully(it) }
    }

    private fun DataOutputStream.writeUtf8(value: String) = writeBytes(value.toByteArray(StandardCharsets.UTF_8))
    private fun DataInputStream.readUtf8(max: Int): String =
        String(readBytes(1, max), StandardCharsets.UTF_8)
}
