package dev.guardian.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class VaultCodecTest {
    @Test fun roundTripAndRejectMalformedFrames() {
        val (header, key) = VaultCrypto.create("password".toCharArray(), KdfParameters(32768, 2, 1))
        val decodedHeader = VaultCodec.decodeHeader(VaultCodec.encodeHeader(header))
        val record = key.use { VaultCrypto.encryptRecord(it, "id", "note", "hello".toByteArray()) }
        key.close()
        val decodedRecord = VaultCodec.decodeRecord(VaultCodec.encodeRecord(record))
        VaultCrypto.unlock(decodedHeader, "password".toCharArray()).use {
            assertArrayEquals("hello".toByteArray(), VaultCrypto.decryptRecord(it, decodedRecord))
        }
        assertThrows(Exception::class.java) { VaultCodec.decodeHeader(VaultCodec.encodeHeader(header) + byteArrayOf(0)) }
        assertThrows(Exception::class.java) { VaultCodec.decodeRecord(VaultCodec.encodeRecord(record).copyOf(20)) }
    }

    /** RFC 9106 section 5.3, including secret and associated data. */
    @Test fun argon2idRfc9106Vector() {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(32).withIterations(3).withParallelism(4)
            .withSalt(ByteArray(16) { 2 }).withSecret(ByteArray(8) { 3 })
            .withAdditional(ByteArray(12) { 4 }).build()
        val output = ByteArray(32)
        Argon2BytesGenerator().apply { init(parameters) }.generateBytes(ByteArray(32) { 1 }, output)
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            output.joinToString("") { "%02x".format(it) })
    }
}
