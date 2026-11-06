package dev.guardian.app

import android.os.Bundle
import android.os.Build
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import dev.guardian.generator.GeneratorOptions
import dev.guardian.generator.PasswordGenerator
import dev.guardian.authenticator.Totp
import dev.guardian.authenticator.TotpUri
import java.util.UUID
import javax.crypto.AEADBadTagException

class MainActivity : ComponentActivity() {
    private lateinit var vault: LocalVault
    private var locked by mutableStateOf(true)
    private var notes by mutableStateOf<List<NoteEntry>>(emptyList())
    private var logins by mutableStateOf<List<LoginSummary>>(emptyList())
    private var error by mutableStateOf<String?>(null)
    private var lockGeneration = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        vault = LocalVault(this)
        setContent {
            val scope = rememberCoroutineScope()
            val dark = isSystemInDarkTheme()
            val colors = if (Build.VERSION.SDK_INT >= 31) {
                if (dark) dynamicDarkColorScheme(this) else dynamicLightColorScheme(this)
            } else if (dark) darkColorScheme() else lightColorScheme()
            MaterialTheme(colorScheme = colors) {
                Surface(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
                    if (locked) {
                        UnlockScreen(vault.exists, error) { password, create ->
                            val generation = lockGeneration
                            scope.launch {
                                val chars = password.toCharArray()
                                try {
                                    if (create) vault.create(chars) else vault.unlock(chars)
                                    if (generation != lockGeneration) {
                                        vault.lock()
                                        return@launch
                                    }
                                    notes = vault.list()
                                    logins = vault.listLogins()
                                    error = null
                                    locked = false
                                } catch (_: AEADBadTagException) {
                                    vault.lock()
                                    error = "Неверный пароль или повреждённое хранилище"
                                } catch (_: Exception) {
                                    vault.lock()
                                    error = "Не удалось открыть хранилище"
                                } finally { chars.fill('\u0000') }
                            }
                        }
                    } else {
                        VaultScreen(notes, logins, error, onSave = { entry, onSuccess ->
                            val generation = lockGeneration
                            scope.launch {
                                try {
                                    vault.save(entry)
                                    if (generation == lockGeneration) {
                                        notes = vault.list()
                                        error = null
                                        onSuccess()
                                    }
                                }
                                catch (_: Exception) { error = "Не удалось сохранить запись" }
                            }
                        }, onOpenLogin = { id, onLoaded ->
                            val generation = lockGeneration
                            scope.launch {
                                try {
                                    val entry = vault.loadLogin(id)
                                    if (generation == lockGeneration) onLoaded(entry)
                                } catch (_: Exception) { error = "Не удалось открыть логин" }
                            }
                        }, onSaveLogin = { entry, onSuccess ->
                            val generation = lockGeneration
                            scope.launch {
                                try {
                                    vault.saveLogin(entry)
                                    if (generation == lockGeneration) {
                                        logins = vault.listLogins()
                                        error = null
                                        onSuccess()
                                    }
                                } catch (_: Exception) { error = "Не удалось сохранить логин" }
                            }
                        }, onLock = { lockNow() })
                    }
                }
            }
        }
    }

    override fun onStop() {
        lockNow()
        super.onStop()
    }

    private fun lockNow() {
        lockGeneration++
        vault.lock()
        notes = emptyList()
        logins = emptyList()
        error = null
        locked = true
    }
}

@Composable
private fun UnlockScreen(exists: Boolean, error: String?, onSubmit: (String, Boolean) -> Unit) {
    var password by remember(exists) { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
        Text("Guardian", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(12.dp))
        Text(if (exists) "Открыть хранилище" else "Создать локальное хранилище")
        if (!exists) Text("Запомните мастер-пароль: восстановление пока не реализовано.")
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(password, { password = it }, label = { Text("Мастер-пароль") },
            visualTransformation = PasswordVisualTransformation(), singleLine = true,
            modifier = Modifier.fillMaxWidth())
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(16.dp))
        Button(onClick = {
            busy = true
            onSubmit(password, !exists)
            password = ""
            busy = false
        }, enabled = !busy && password.length >= if (exists) 1 else 12) {
            Text(if (exists) "Открыть" else "Создать")
        }
    }
}

@Composable
private fun VaultScreen(
    notes: List<NoteEntry>, logins: List<LoginSummary>, error: String?,
    onSave: (NoteEntry, () -> Unit) -> Unit,
    onOpenLogin: (String, (LoginEntry) -> Unit) -> Unit,
    onSaveLogin: (LoginEntry, () -> Unit) -> Unit,
    onLock: () -> Unit,
) {
    var selected by remember { mutableStateOf<NoteEntry?>(null) }
    var title by remember(selected) { mutableStateOf(selected?.title ?: "") }
    var body by remember(selected) { mutableStateOf(selected?.body ?: "") }
    var showTrash by remember { mutableStateOf(false) }
    var showGenerator by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var tab by remember { mutableStateOf("logins") }
    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Моё хранилище", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = onLock) { Text("Блокировать") }
        }
        Text("Логины и заметки · локально", style = MaterialTheme.typography.bodyMedium)
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Row {
            TextButton(onClick = { tab = "logins" }) { Text("Логины") }
            TextButton(onClick = { tab = "notes" }) { Text("Заметки") }
        }
        if (tab == "logins") {
            LoginScreen(logins, onOpenLogin, onSaveLogin)
        } else if (showGenerator) {
            GeneratorScreen(onSave = { password, onSuccess ->
                onSave(NoteEntry(UUID.randomUUID().toString(), "Сгенерированный пароль", password)) {
                    onSuccess()
                    showGenerator = false
                }
            }, onClose = { showGenerator = false })
        } else if (selected == null) {
            OutlinedTextField(query, { query = it }, label = { Text("Поиск заметок") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Row {
                TextButton(onClick = { showTrash = false }) { Text("Записи") }
                TextButton(onClick = { showTrash = true }) { Text("Корзина") }
            }
            Row {
                TextButton(onClick = { selected = NoteEntry(UUID.randomUUID().toString(), "", "") }) { Text("Добавить") }
                TextButton(onClick = { showGenerator = true }) { Text("Генератор") }
            }
            val visible = notes.filter {
                it.deleted == showTrash && (query.isBlank() ||
                    it.title.contains(query, ignoreCase = true) || it.body.contains(query, ignoreCase = true))
            }
            if (visible.isEmpty()) Text("Здесь пока нет записей", Modifier.padding(16.dp))
            LazyColumn {
                items(visible, key = { it.id }) { note ->
                    ListItem(headlineContent = { Text(note.title.ifBlank { "Без названия" }) },
                        modifier = Modifier.fillMaxWidth(),
                        trailingContent = {
                            TextButton(onClick = { selected = note }) { Text("Открыть") }
                        })
                    HorizontalDivider()
                }
            }
        } else {
            val current = selected!!
            OutlinedTextField(title, { title = it }, label = { Text("Название") }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(body, { body = it }, label = { Text("Текст") },
                modifier = Modifier.fillMaxWidth().weight(1f))
            Row {
                Button(onClick = { onSave(current.copy(title = title, body = body)) { selected = null } }) { Text("Сохранить") }
                TextButton(onClick = { selected = null }) { Text("Отмена") }
                TextButton(onClick = {
                    onSave(current.copy(title = title, body = body, deleted = !current.deleted)) { selected = null }
                }) { Text(if (current.deleted) "Восстановить" else "В корзину") }
            }
        }
    }
}

@Composable
private fun GeneratorScreen(onSave: (String, () -> Unit) -> Unit, onClose: () -> Unit) {
    val generator = remember { PasswordGenerator() }
    var length by remember { mutableIntStateOf(20) }
    var useSymbols by remember { mutableStateOf(true) }
    var excludeAmbiguous by remember { mutableStateOf(false) }
    var generated by remember { mutableStateOf("") }
    Column {
        Text("Генератор паролей", style = MaterialTheme.typography.titleLarge)
        Text("Длина: $length")
        Slider(value = length.toFloat(), onValueChange = { length = it.toInt() }, valueRange = 12f..64f)
        Row { Text("Специальные символы"); Switch(checked = useSymbols, onCheckedChange = { useSymbols = it }) }
        Row { Text("Без похожих символов"); Switch(checked = excludeAmbiguous, onCheckedChange = { excludeAmbiguous = it }) }
        Button(onClick = {
            val chars = generator.generate(GeneratorOptions(length = length,
                symbols = useSymbols, excludeAmbiguous = excludeAmbiguous))
            try { generated = String(chars) } finally { chars.fill('\u0000') }
        }) { Text("Создать пароль") }
        if (generated.isNotEmpty()) {
            Text(generated, style = MaterialTheme.typography.bodyLarge)
            Button(onClick = { onSave(generated) { generated = "" } }) { Text("Сохранить в хранилище") }
        }
        TextButton(onClick = { generated = ""; onClose() }) { Text("Назад") }
    }
}

@Composable
private fun LoginScreen(
    logins: List<LoginSummary>,
    onOpen: (String, (LoginEntry) -> Unit) -> Unit,
    onSave: (LoginEntry, () -> Unit) -> Unit,
) {
    var selected by remember { mutableStateOf<LoginEntry?>(null) }
    var showTrash by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    if (selected == null) {
        OutlinedTextField(query, { query = it }, label = { Text("Поиск логинов") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        Row {
            TextButton(onClick = { showTrash = false }) { Text("Записи") }
            TextButton(onClick = { showTrash = true }) { Text("Корзина") }
            TextButton(onClick = {
                selected = LoginEntry(UUID.randomUUID().toString(), "", "", "", "")
            }) { Text("Добавить") }
        }
        val visible = logins.filter {
            it.deleted == showTrash && (query.isBlank() || it.title.contains(query, true) ||
                it.username.contains(query, true) || it.url.contains(query, true))
        }
        if (visible.isEmpty()) Text("Здесь пока нет логинов", Modifier.padding(16.dp))
        LazyColumn {
            items(visible, key = { it.id }) { login ->
                ListItem(headlineContent = { Text(login.title.ifBlank { "Без названия" }) },
                    supportingContent = { Text(login.username) },
                    trailingContent = {
                        TextButton(onClick = { onOpen(login.id) { selected = it } }) { Text("Открыть") }
                    })
                HorizontalDivider()
            }
        }
    } else {
        val current = selected!!
        var title by remember(current) { mutableStateOf(current.title) }
        var username by remember(current) { mutableStateOf(current.username) }
        var password by remember(current) { mutableStateOf(current.password) }
        var url by remember(current) { mutableStateOf(current.url) }
        var totpUri by remember(current) { mutableStateOf(current.totpUri) }
        var showPassword by remember(current) { mutableStateOf(false) }
        var seconds by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
        LaunchedEffect(current.id) {
            while (true) {
                seconds = System.currentTimeMillis() / 1000
                delay(1_000)
            }
        }
        val totpConfig = remember(totpUri) {
            if (totpUri.isBlank()) null else runCatching { TotpUri.parse(totpUri) }.getOrNull()
        }
        DisposableEffect(totpConfig) {
            onDispose { totpConfig?.close() }
        }
        Column(Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(title, { title = it }, label = { Text("Сервис") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(username, { username = it }, label = { Text("Логин или email") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(password, { password = it }, label = { Text("Пароль") },
                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth())
            TextButton(onClick = { showPassword = !showPassword }) {
                Text(if (showPassword) "Скрыть пароль" else "Показать пароль")
            }
            OutlinedTextField(url, { url = it }, label = { Text("URL") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(totpUri, { totpUri = it }, label = { Text("otpauth:// URI для 2FA") },
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            if (totpUri.isNotBlank() && totpConfig == null) {
                Text("Некорректный TOTP URI", color = MaterialTheme.colorScheme.error)
            }
            if (totpConfig != null) {
                Text(Totp.code(totpConfig, seconds), style = MaterialTheme.typography.headlineMedium)
                Text("Смена через ${Totp.remainingSeconds(seconds, totpConfig.periodSeconds)} с · проверьте время устройства")
                Text("Пароль и второй фактор в одном хранилище повышают риск при его компрометации.")
            }
            Row {
                Button(onClick = {
                    onSave(current.copy(title = title, username = username, password = password,
                        url = url, totpUri = totpUri)) {
                        selected = null
                    }
                }, enabled = totpUri.isBlank() || totpConfig != null) { Text("Сохранить") }
                TextButton(onClick = { selected = null }) { Text("Отмена") }
            }
            TextButton(onClick = {
                onSave(current.copy(title = title, username = username, password = password, url = url,
                    deleted = !current.deleted, totpUri = totpUri)) { selected = null }
            }) { Text(if (current.deleted) "Восстановить" else "В корзину") }
        }
    }
}
