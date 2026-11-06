# Проверенные источники, 2026-11-05

- Android Credential Provider: https://developer.android.com/identity/sign-in/credential-provider
- Android AutofillService: https://developer.android.com/identity/autofill/autofill-services
- OWASP MASVS: https://mas.owasp.org/MASVS/
- TOTP и тестовые векторы: https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B
- Argon2id и тестовый вектор: https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3
- Maven metadata AGP: https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/maven-metadata.xml
- Maven metadata Compose BOM: https://dl.google.com/dl/android/maven2/androidx/compose/compose-bom/maven-metadata.xml
- Maven metadata Bouncy Castle: https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/maven-metadata.xml

В исходниках закреплены AGP 9.5.1, Kotlin 2.3.21, Compose BOM 2026.09.00, Bouncy Castle 1.86. Из-за требований AndroidX к compile SDK используется Android SDK Platform 37.2; минимальный SDK 29 и target SDK 36. Перед релизом требуется повторная проверка CVE, сопровождения и лицензий всех прямых и транзитивных зависимостей.
