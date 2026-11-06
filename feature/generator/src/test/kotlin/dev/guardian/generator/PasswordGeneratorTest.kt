package dev.guardian.generator

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PasswordGeneratorTest {
    @Test fun respectsAllSelectedClassesAndExclusions() {
        val generator = PasswordGenerator()
        val options = GeneratorOptions(length = 32, excludeAmbiguous = true, excluded = "@#")
        repeat(500) {
            val password = generator.generate(options)
            assertEquals(32, password.size)
            assertTrue(password.any(Char::isLowerCase))
            assertTrue(password.any(Char::isUpperCase))
            assertTrue(password.any(Char::isDigit))
            assertTrue(password.any { it in "!$%^&*()-_=+[]{};:,.?/|" })
            assertTrue(password.none { it in "Il1O0o@#" })
            password.fill('\u0000')
        }
    }

    @Test fun rejectsImpossibleSettingsAndProducesDifferentOutputs() {
        val generator = PasswordGenerator()
        assertThrows(IllegalArgumentException::class.java) {
            generator.generate(GeneratorOptions(lowercase = false, uppercase = false,
                digits = false, symbols = false))
        }
        val outputs = (0 until 100).map { String(generator.generate()) }
        assertEquals(100, outputs.toSet().size)
    }
}
