# Guardian

Ранняя версия локального Android менеджера секретов. **Не используйте для реальных паролей до независимого аудита и проверки восстановления.** Сейчас доступны создание хранилища, мастер-пароль, зашифрованные логины и заметки, просмотр/редактирование, корзина, поиск, генератор паролей, ручной импорт TOTP через `otpauth://` и блокировка при уходе в фон. Биометрия, системное автозаполнение, passkeys, QR-сканирование TOTP, импорт/экспорт и синхронизация ещё не реализованы.

## Сборка

Нужны JDK 21 и Android SDK Platform 37.2, Build Tools 36.0.0. Укажите SDK через `ANDROID_HOME` либо `local.properties` (`sdk.dir=/путь/к/sdk`).

- Fedora: `sudo dnf install java-21-openjdk-devel android-tools`; установите Android Command Line Tools с developer.android.com/studio, затем `sdkmanager 'platforms;android-37.2' 'build-tools;36.0.0' 'platform-tools'`.
- Manjaro: `sudo pacman -S jdk21-openjdk android-tools`; Android SDK пакеты установите через официальные Command Line Tools той же командой.
- Сборка и тесты: `./gradlew :core:crypto:test :app:assembleDebug`.
- Установка в отдельный тестовый профиль: `adb install app/build/outputs/apk/debug/app-debug.apk`. Для синтетического теста на эмуляторе: `ANDROID_HOME=/путь/к/sdk scripts/verify_emulator.sh emulator-5554` (скрипт отказывает физическим устройствам).

Debug APK: `app/build/outputs/apk/debug/app-debug.apk` после сборки. Release сборка `app/build/outputs/apk/release/app-release-unsigned.apk` собирается с R8 и не содержит ключей подписи; она не предназначена для публикации. Для рабочего релиза нужны аудит, резервное копирование, миграции, инструментальные тесты и отдельная подпись вне репозитория.

## Документы

- [Архитектура](docs/ARCHITECTURE.md)
- [Модель угроз](docs/THREAT_MODEL.md)
- [Криптографический формат](docs/CRYPTO_FORMAT.md)
- [Результаты тестов](docs/TEST_RESULTS.md)
- [Примечания к тестовому выпуску](docs/RELEASE_PREVIEW.md)
- [План работ](docs/ROADMAP.md)
- [Проверенные источники](docs/RESEARCH.md)
- [Текущая проверка безопасности](docs/SECURITY_REVIEW.md)
- [Восстановление данных](docs/RECOVERY.md)
