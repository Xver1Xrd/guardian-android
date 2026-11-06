package dev.guardian.generator

import java.security.SecureRandom

/** Uniform sampling over passwords that satisfy the selected character-class constraints. */
data class GeneratorOptions(
    val length: Int = 20,
    val lowercase: Boolean = true,
    val uppercase: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val excludeAmbiguous: Boolean = false,
    val excluded: String = "",
) {
    init { require(length in 8..128) }
}

class PasswordGenerator(private val random: SecureRandom = SecureRandom()) {
    fun generate(options: GeneratorOptions = GeneratorOptions()): CharArray {
        val groups = buildList {
            if (options.lowercase) add("abcdefghijklmnopqrstuvwxyz")
            if (options.uppercase) add("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            if (options.digits) add("0123456789")
            if (options.symbols) add("!@#$%^&*()-_=+[]{};:,.?/|")
        }.map { group -> group.filterNot { it in options.excluded ||
            (options.excludeAmbiguous && it in "Il1O0o") }.toCharArray() }
        require(groups.isNotEmpty() && groups.all { it.isNotEmpty() }) { "No usable character classes" }
        require(options.length >= groups.size)
        val alphabet = groups.flatMap { it.asIterable() }.toCharArray()
        // Rejection of complete candidates preserves a uniform distribution over valid passwords.
        repeat(100_000) {
            val candidate = CharArray(options.length) { alphabet[random.nextInt(alphabet.size)] }
            if (groups.all { group -> candidate.any { it in group } }) return candidate
            candidate.fill('\u0000')
        }
        error("Could not generate a password with these constraints")
    }
}
