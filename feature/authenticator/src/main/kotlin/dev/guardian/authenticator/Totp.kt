package dev.guardian.authenticator

import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class TotpAlgorithm(val jcaName: String) {
    SHA1("HmacSHA1"), SHA256("HmacSHA256"), SHA512("HmacSHA512")
}

class TotpConfig(
    val account: String,
    val issuer: String?,
    secret: ByteArray,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
    val algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
) : AutoCloseable {
    private val secretBytes = secret.clone()
    private var closed = false
    init {
        require(account.isNotBlank() && account.length <= 512)
        require(issuer == null || issuer.length <= 256)
        require(secretBytes.size in 10..512)
        require(digits in 6..8 && periodSeconds in 1..300)
    }
    fun secretCopy(): ByteArray = synchronized(this) {
        check(!closed) { "TOTP configuration is closed" }
        secretBytes.clone()
    }
    override fun close() = synchronized(this) {
        secretBytes.fill(0)
        closed = true
    }
}

object Totp {
    fun code(config: TotpConfig, epochSeconds: Long): String {
        val secret = config.secretCopy()
        try { return code(secret, epochSeconds, config.digits, config.periodSeconds, config.algorithm) }
        finally { secret.fill(0) }
    }

    fun code(secret: ByteArray, epochSeconds: Long, digits: Int = 6, periodSeconds: Int = 30,
             algorithm: TotpAlgorithm = TotpAlgorithm.SHA1): String {
        require(secret.size in 10..512 && digits in 6..8 && periodSeconds in 1..300 && epochSeconds >= 0)
        val counter = epochSeconds / periodSeconds
        val message = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance(algorithm.jcaName)
        mac.init(SecretKeySpec(secret, algorithm.jcaName))
        val digest = mac.doFinal(message)
        val offset = digest.last().toInt() and 0x0f
        val binary = ((digest[offset].toInt() and 0x7f) shl 24) or
            ((digest[offset + 1].toInt() and 0xff) shl 16) or
            ((digest[offset + 2].toInt() and 0xff) shl 8) or
            (digest[offset + 3].toInt() and 0xff)
        val modulus = (1..digits).fold(1) { value, _ -> value * 10 }
        digest.fill(0)
        message.fill(0)
        return (binary % modulus).toString().padStart(digits, '0')
    }

    fun remainingSeconds(epochSeconds: Long, periodSeconds: Int): Int {
        require(epochSeconds >= 0 && periodSeconds in 1..300)
        return periodSeconds - (epochSeconds % periodSeconds).toInt()
    }
}

/** Strict importer for otpauth://totp URIs; HOTP and unsupported parameters are rejected. */
object TotpUri {
    fun parse(value: String): TotpConfig {
        require(value.length <= 8192)
        val uri = URI(value)
        require(uri.scheme.equals("otpauth", ignoreCase = true) && uri.host.equals("totp", ignoreCase = true))
        val label = decode(uri.rawPath?.removePrefix("/") ?: "")
        require(label.isNotBlank())
        val parameters = (uri.rawQuery ?: "").split('&').filter { it.isNotBlank() }.associate { part ->
            val pair = part.split('=', limit = 2)
            require(pair.size == 2)
            decode(pair[0]).lowercase() to decode(pair[1])
        }
        require(parameters.size == (uri.rawQuery ?: "").split('&').count { it.isNotBlank() }) {
            "Duplicate otpauth parameter"
        }
        val secret = decodeBase32(parameters["secret"] ?: error("Missing TOTP secret"))
        try {
            val issuer = parameters["issuer"]?.takeIf { it.isNotBlank() }
            val labelIssuer = label.substringBefore(':', "").takeIf { it.isNotBlank() }
            require(issuer == null || labelIssuer == null || issuer == labelIssuer)
            val account = if (labelIssuer == null) label else label.substringAfter(':').trim()
            val algorithm = when (parameters["algorithm"]?.uppercase() ?: "SHA1") {
                "SHA1" -> TotpAlgorithm.SHA1
                "SHA256" -> TotpAlgorithm.SHA256
                "SHA512" -> TotpAlgorithm.SHA512
                else -> error("Unsupported TOTP algorithm")
            }
            return TotpConfig(account, issuer ?: labelIssuer, secret,
                parameters["digits"]?.toInt() ?: 6, parameters["period"]?.toInt() ?: 30, algorithm)
        } finally { secret.fill(0) }
    }

    private fun decode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8.name())

    private fun decodeBase32(value: String): ByteArray {
        val normalized = value.trim().trimEnd('=').uppercase()
        require(normalized.isNotEmpty() && normalized.length <= 1024)
        val result = ArrayList<Byte>(normalized.length * 5 / 8)
        var bits = 0
        var buffer = 0
        for (char in normalized) {
            val digit = when (char) {
                in 'A'..'Z' -> char - 'A'
                in '2'..'7' -> char - '2' + 26
                else -> error("Invalid Base32 secret")
            }
            buffer = (buffer shl 5) or digit
            bits += 5
            if (bits >= 8) {
                bits -= 8
                result.add(((buffer shr bits) and 0xff).toByte())
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        require(buffer == 0) { "Nonzero Base32 padding bits" }
        return result.toByteArray()
    }
}
