package dev.guardian.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import javax.crypto.AEADBadTagException

class VaultCryptoTest {
    private val fast = KdfParameters(memoryKiB = 32768, iterations = 2)

    @Test fun createUnlockAndBindMetadata() {
        val password = "correct horse battery staple".toCharArray()
        val (header, key) = VaultCrypto.create(password, fast)
        key.use {
            val item = VaultCrypto.encryptRecord(it, "record-1", "login", "secret".toByteArray())
            assertArrayEquals("secret".toByteArray(), VaultCrypto.decryptRecord(it, item))
            assertThrows(AEADBadTagException::class.java) {
                VaultCrypto.decryptRecord(it, CipherRecord(item.version, "record-2", item.kind, item.nonce, item.ciphertext))
            }
            assertThrows(AEADBadTagException::class.java) {
                VaultCrypto.decryptRecord(it, CipherRecord(item.version, item.id, "note", item.nonce, item.ciphertext))
            }
        }
        VaultCrypto.unlock(header, password).use { unlocked ->
            assertArrayEquals("hello".toByteArray(), VaultCrypto.decryptRecord(unlocked,
                VaultCrypto.encryptRecord(unlocked, "a", "note", "hello".toByteArray())))
        }
        assertThrows(AEADBadTagException::class.java) { VaultCrypto.unlock(header, "wrong".toCharArray()) }
    }

    @Test fun tamperingAndUniqueNonces() {
        val (header, key) = VaultCrypto.create("master".toCharArray(), fast)
        key.use {
            val records = (0 until 1000).map { n -> VaultCrypto.encryptRecord(it, "$n", "login", byteArrayOf(1)) }
            assertEquals(records.size, records.map { r -> r.nonce.toList() }.toSet().size)
            val r = records.first()
            val damaged = r.ciphertext.clone().also { bytes -> bytes[0] = (bytes[0].toInt() xor 1).toByte() }
            assertThrows(AEADBadTagException::class.java) {
                VaultCrypto.decryptRecord(it, CipherRecord(r.version, r.id, r.kind, r.nonce, damaged))
            }
        }
        val bad = header.wrappedKey.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows(AEADBadTagException::class.java) {
            VaultCrypto.unlock(VaultHeader(header.version, header.salt, header.kdf, header.nonce, bad), "master".toCharArray())
        }
    }

    @Test fun changingPasswordPreservesRecords() {
        val old = "old password".toCharArray()
        val fresh = "new password".toCharArray()
        val (header, key) = VaultCrypto.create(old, fast)
        val record = key.use { VaultCrypto.encryptRecord(it, "1", "login", "data".toByteArray()) }
        key.close()
        val updated = VaultCrypto.changePassword(header, old, fresh, fast)
        assertThrows(AEADBadTagException::class.java) { VaultCrypto.unlock(updated, old) }
        VaultCrypto.unlock(updated, fresh).use {
            assertArrayEquals("data".toByteArray(), VaultCrypto.decryptRecord(it, record))
        }
    }
}
