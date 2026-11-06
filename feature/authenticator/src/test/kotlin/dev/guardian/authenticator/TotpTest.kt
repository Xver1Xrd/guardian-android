package dev.guardian.authenticator

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class TotpTest {
    @Test fun rfc6238AppendixBVectors() {
        val sha1 = "12345678901234567890".toByteArray()
        val sha256 = "12345678901234567890123456789012".toByteArray()
        val sha512 = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()
        assertEquals("94287082", Totp.code(sha1, 59, 8, algorithm = TotpAlgorithm.SHA1))
        assertEquals("46119246", Totp.code(sha256, 59, 8, algorithm = TotpAlgorithm.SHA256))
        assertEquals("90693936", Totp.code(sha512, 59, 8, algorithm = TotpAlgorithm.SHA512))
        assertEquals("07081804", Totp.code(sha1, 1111111109, 8, algorithm = TotpAlgorithm.SHA1))
        assertEquals("68084774", Totp.code(sha256, 1111111109, 8, algorithm = TotpAlgorithm.SHA256))
        assertEquals("25091201", Totp.code(sha512, 1111111109, 8, algorithm = TotpAlgorithm.SHA512))
    }

    @Test fun parsesOtpauthAndRejectsInvalidInput() {
        val config = TotpUri.parse("otpauth://totp/Example:alice%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30")
        assertEquals("alice@example.test", config.account)
        assertEquals("Example", config.issuer)
        assertEquals(6, Totp.code(config, 59).length)
        assertEquals(1, Totp.remainingSeconds(59, 30))
        config.close()
        assertThrows(IllegalStateException::class.java) { config.secretCopy() }
        assertThrows(Exception::class.java) { TotpUri.parse("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP") }
        assertThrows(Exception::class.java) { TotpUri.parse("otpauth://totp/a?secret=%%%%") }
        assertThrows(Exception::class.java) { TotpUri.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP") }
    }
}
