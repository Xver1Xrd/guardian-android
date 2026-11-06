package dev.guardian.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.guardian.authenticator.Totp
import dev.guardian.authenticator.TotpUri
import dev.guardian.generator.GeneratorOptions
import dev.guardian.generator.PasswordGenerator
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID
import javax.crypto.AEADBadTagException

private val GuardianAmoled = darkColorScheme(
    primary = Color(0xFFB7F7C2), onPrimary = Color(0xFF003914),
    primaryContainer = Color(0xFF075421), onPrimaryContainer = Color(0xFFD4FFD6),
    secondary = Color(0xFF9DD8FF), onSecondary = Color(0xFF00344F),
    error = Color(0xFFFFB4AB), background = Color.Black, surface = Color.Black,
    onBackground = Color(0xFFE5E3E6), onSurface = Color(0xFFE5E3E6),
    surfaceVariant = Color(0xFF1C1D20), onSurfaceVariant = Color(0xFFC8C5CA),
    outline = Color(0xFF928F96),
)
private val PanelShape = RoundedCornerShape(24.dp)

class MainActivity : ComponentActivity() {
    private lateinit var vault: LocalVault
    private lateinit var biometricVault: BiometricVault
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
        biometricVault = BiometricVault(this)
        setContent {
            val scope = rememberCoroutineScope()
            val biometricAvailable = remember { biometricVault.canAuthenticate() }
            MaterialTheme(colorScheme = GuardianAmoled) {
                Surface(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing), color = Color.Black) {
                    AnimatedContent(
                        targetState = locked,
                        transitionSpec = {
                            (fadeIn(tween(220)) + slideInHorizontally(tween(260), initialOffsetX = { it / 12 })) togetherWith
                                (fadeOut(tween(140)) + slideOutHorizontally(tween(180), targetOffsetX = { -it / 12 }))
                        }, label = "lock-state"
                    ) { isLocked ->
                        if (isLocked) UnlockScreen(
                            exists = vault.exists,
                            biometricAvailable = biometricAvailable,
                            biometricEnabled = biometricVault.isEnabled,
                            error = error,
                            onBiometric = {
                                biometricVault.unlock(this@MainActivity, onPassword = { chars ->
                                    val generation = lockGeneration
                                    scope.launch {
                                        try {
                                            vault.unlock(chars)
                                            if (generation != lockGeneration) { vault.lock(); return@launch }
                                            notes = vault.list(); logins = vault.listLogins(); error = null; locked = false
                                        } catch (_: Exception) {
                                            vault.lock(); error = "Не удалось открыть хранилище по отпечатку"
                                        } finally { chars.fill('\u0000') }
                                    }
                                }, onError = { error = it })
                            },
                        ) { password, create, enableBiometric, finished ->
                            val generation = lockGeneration
                            scope.launch {
                                val chars = password.toCharArray()
                                try {
                                    if (create) vault.create(chars) else vault.unlock(chars)
                                    if (generation != lockGeneration) { vault.lock(); return@launch }
                                    notes = vault.list(); logins = vault.listLogins(); error = null; locked = false
                                    if (enableBiometric) biometricVault.enable(this@MainActivity, chars) { error = it }
                                } catch (_: AEADBadTagException) {
                                    vault.lock(); error = "Неверный пароль или повреждённое хранилище"
                                } catch (_: Exception) {
                                    vault.lock(); error = "Не удалось открыть хранилище"
                                } finally { chars.fill('\u0000'); finished() }
                            }
                        } else VaultScreen(notes, logins, error,
                            onSaveNote = { entry, done -> saveNote(scope, entry, done) },
                            onOpenLogin = { id, loaded -> openLogin(scope, id, loaded) },
                            onSaveLogin = { entry, done -> saveLogin(scope, entry, done) },
                            onLock = ::lockNow)
                    }
                }
            }
        }
    }
    private fun saveNote(scope: kotlinx.coroutines.CoroutineScope, entry: NoteEntry, done: () -> Unit) = scope.launch {
        val generation = lockGeneration
        try { vault.save(entry); if (generation == lockGeneration) { notes = vault.list(); error = null; done() } }
        catch (_: Exception) { error = "Не удалось сохранить запись" }
    }
    private fun openLogin(scope: kotlinx.coroutines.CoroutineScope, id: String, loaded: (LoginEntry) -> Unit) = scope.launch {
        val generation = lockGeneration
        try { val entry = vault.loadLogin(id); if (generation == lockGeneration) loaded(entry) }
        catch (_: Exception) { error = "Не удалось открыть логин" }
    }
    private fun saveLogin(scope: kotlinx.coroutines.CoroutineScope, entry: LoginEntry, done: () -> Unit) = scope.launch {
        val generation = lockGeneration
        try { vault.saveLogin(entry); if (generation == lockGeneration) { logins = vault.listLogins(); error = null; done() } }
        catch (_: Exception) { error = "Не удалось сохранить логин" }
    }
    override fun onStop() { lockNow(); super.onStop() }
    private fun lockNow() { lockGeneration++; vault.lock(); notes = emptyList(); logins = emptyList(); error = null; locked = true }
}

@Composable private fun UnlockScreen(
    exists: Boolean,
    biometricAvailable: Boolean,
    biometricEnabled: Boolean,
    error: String?,
    onBiometric: () -> Unit,
    submit: (String, Boolean, Boolean, () -> Unit) -> Unit,
) {
    var password by remember(exists) { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var enableBiometric by remember(exists, biometricEnabled) { mutableStateOf(biometricAvailable && !biometricEnabled) }
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp).navigationBarsPadding(), verticalArrangement = Arrangement.Center) {
        Box(Modifier.size(58.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primaryContainer), contentAlignment = Alignment.Center) {
            Text("G", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(28.dp))
        Text("Guardian", style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold)
        Text(if (exists) "Ваше локальное хранилище готово к открытию." else "Создайте ключ к локальному хранилищу.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(28.dp))
        Panel {
            Text(if (exists) "Открыть хранилище" else "Новый мастер-пароль", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(16.dp))
            VaultField(password, { password = it.take(10) }, "Мастер-пароль · максимум 10 символов", secret = true, singleLine = true)
            AnimatedVisibility(error != null) { Text(error.orEmpty(), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 12.dp)) }
            if (!exists) Text("От 1 до 10 символов. Восстановление пока не реализовано.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 12.dp))
            if (biometricAvailable && !biometricEnabled) SwitchLine("Включить вход по отпечатку", enableBiometric) { enableBiometric = it }
            Spacer(Modifier.height(20.dp))
            Button(onClick = { busy = true; submit(password, !exists, enableBiometric) { busy = false }; password = "" }, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
                Text(if (busy) "Открываем…" else if (exists) "Открыть" else "Создать хранилище")
            }
            if (exists && biometricEnabled) {
                TextButton(onClick = onBiometric, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Войти по отпечатку") }
            }
        }
    }
}

private enum class Tab(val label: String) { LOGINS("Логины"), NOTES("Заметки") }
@Composable private fun VaultScreen(notes: List<NoteEntry>, logins: List<LoginSummary>, error: String?, onSaveNote: (NoteEntry, () -> Unit) -> Unit, onOpenLogin: (String, (LoginEntry) -> Unit) -> Unit, onSaveLogin: (LoginEntry, () -> Unit) -> Unit, onLock: () -> Unit) {
    var tab by remember { mutableStateOf(Tab.LOGINS) }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp).navigationBarsPadding()) {
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) { Text("Моё хранилище", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold); Text("Локально · зашифровано", color = MaterialTheme.colorScheme.primary) }
            TextButton(onClick = onLock) { Text("Блокировать") }
        }
        AnimatedVisibility(error != null) { Text(error.orEmpty(), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp)) }
        Spacer(Modifier.height(16.dp)); TabBar(tab) { tab = it }; Spacer(Modifier.height(16.dp))
        AnimatedContent(targetState = tab, transitionSpec = { (fadeIn(tween(180)) + slideInHorizontally(tween(220), initialOffsetX = { it / 12 })) togetherWith (fadeOut(tween(110)) + slideOutHorizontally(tween(160), targetOffsetX = { -it / 12 })) }, label = "tab") { active ->
            if (active == Tab.LOGINS) LoginScreen(logins, onOpenLogin, onSaveLogin) else NotesScreen(notes, onSaveNote)
        }
    }
}
@Composable private fun TabBar(selected: Tab, choose: (Tab) -> Unit) = Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
    Row(Modifier.fillMaxWidth().padding(4.dp)) { Tab.entries.forEach { tab ->
        Surface(Modifier.weight(1f).clip(RoundedCornerShape(14.dp)).clickable { choose(tab) }, shape = RoundedCornerShape(14.dp), color = if (tab == selected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent) {
            Text(tab.label, Modifier.padding(vertical = 10.dp), textAlign = TextAlign.Center, color = if (tab == selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = if (tab == selected) FontWeight.SemiBold else FontWeight.Normal)
        }
    } }
}

@Composable private fun NotesScreen(notes: List<NoteEntry>, save: (NoteEntry, () -> Unit) -> Unit) {
    var entry by remember { mutableStateOf<NoteEntry?>(null) }; var query by remember { mutableStateOf("") }; var trash by remember { mutableStateOf(false) }; var generator by remember { mutableStateOf(false) }
    val visible by remember(notes, query, trash) { derivedStateOf { notes.filter { it.deleted == trash && (query.isBlank() || it.title.contains(query, true) || it.body.contains(query, true)) } } }
    AnimatedContent(entry to generator, label = "notes") { (selected, generating) -> when {
        generating -> GeneratorScreen({ password, title, done -> save(NoteEntry(UUID.randomUUID().toString(), title, password)) { done(); generator = false } }) { generator = false }
        selected != null -> NoteEditor(selected, { save(it) { entry = null } }) { entry = null }
        else -> EntryList(query, { query = it }, trash, { trash = it }, visible, if (trash) "Корзина пуста" else "Здесь пока нет заметок", "Новая заметка", { entry = NoteEntry(UUID.randomUUID().toString(), "", "") }, "Генератор", { generator = true }) { note -> VaultRow(note.title.ifBlank { "Без названия" }, note.body) { entry = note } }
    } }
}
@Composable private fun NoteEditor(entry: NoteEntry, save: (NoteEntry) -> Unit, close: () -> Unit) {
    var title by remember(entry.id) { mutableStateOf(entry.title) }; var body by remember(entry.id) { mutableStateOf(entry.body) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) { EditorHeader("Заметка", close); VaultField(title, { title = it }, "Название"); VaultField(body, { body = it }, "Текст", minLines = 8); Button({ save(entry.copy(title = title, body = body)) }, Modifier.fillMaxWidth()) { Text("Сохранить") }; TextButton({ save(entry.copy(title = title, body = body, deleted = !entry.deleted)) }, Modifier.fillMaxWidth()) { Text(if (entry.deleted) "Восстановить из корзины" else "Переместить в корзину") } }
}

@Composable private fun LoginScreen(logins: List<LoginSummary>, open: (String, (LoginEntry) -> Unit) -> Unit, save: (LoginEntry, () -> Unit) -> Unit) {
    var entry by remember { mutableStateOf<LoginEntry?>(null) }; var query by remember { mutableStateOf("") }; var trash by remember { mutableStateOf(false) }
    val visible by remember(logins, query, trash) { derivedStateOf { logins.filter { it.deleted == trash && (query.isBlank() || it.title.contains(query, true) || it.username.contains(query, true) || it.url.contains(query, true)) } } }
    AnimatedContent(entry, label = "logins") { selected -> if (selected == null) EntryList(query, { query = it }, trash, { trash = it }, visible, if (trash) "Корзина пуста" else "Здесь пока нет логинов", "Новый логин", { entry = LoginEntry(UUID.randomUUID().toString(), "", "", "", "") }) { login -> VaultRow(login.title.ifBlank { "Без названия" }, login.username.ifBlank { login.url }) { open(login.id) { entry = it } } } else LoginEditor(selected, { save(it) { entry = null } }) { entry = null } }
}
@Composable private fun LoginEditor(entry: LoginEntry, save: (LoginEntry) -> Unit, close: () -> Unit) {
    var title by remember(entry.id) { mutableStateOf(entry.title) }; var username by remember(entry.id) { mutableStateOf(entry.username) }; var password by remember(entry.id) { mutableStateOf(entry.password) }; var url by remember(entry.id) { mutableStateOf(entry.url) }; var totpUri by remember(entry.id) { mutableStateOf(entry.totpUri) }; var reveal by remember(entry.id) { mutableStateOf(false) }; var seconds by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(entry.id) { while (true) { seconds = System.currentTimeMillis() / 1000; delay(1_000) } }
    val totp = remember(totpUri) { if (totpUri.isBlank()) null else runCatching { TotpUri.parse(totpUri) }.getOrNull() }; DisposableEffect(totp) { onDispose { totp?.close() } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) { EditorHeader("Логин", close); VaultField(title, { title = it }, "Сервис"); VaultField(username, { username = it }, "Логин или email"); VaultField(password, { password = it }, "Пароль", secret = !reveal); TextButton({ reveal = !reveal }) { Text(if (reveal) "Скрыть пароль" else "Показать пароль") }; VaultField(url, { url = it }, "URL"); VaultField(totpUri, { totpUri = it }, "otpauth:// URI для 2FA", secret = true)
        if (totpUri.isNotBlank() && totp == null) Text("Некорректный TOTP URI", color = MaterialTheme.colorScheme.error)
        if (totp != null) Panel { Text(Totp.code(totp, seconds), style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary); Text("Смена через ${Totp.remainingSeconds(seconds, totp.periodSeconds)} с", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        Button({ save(entry.copy(title = title, username = username, password = password, url = url, totpUri = totpUri)) }, Modifier.fillMaxWidth(), enabled = totpUri.isBlank() || totp != null) { Text("Сохранить") }; TextButton({ save(entry.copy(title = title, username = username, password = password, url = url, totpUri = totpUri, deleted = !entry.deleted)) }, Modifier.fillMaxWidth()) { Text(if (entry.deleted) "Восстановить из корзины" else "Переместить в корзину") }
    }
}

@Composable private fun GeneratorScreen(save: (String, String, () -> Unit) -> Unit, close: () -> Unit) {
    val generator = remember { PasswordGenerator() }; var length by remember { mutableIntStateOf(20) }; var symbols by remember { mutableStateOf(true) }; var ambiguous by remember { mutableStateOf(false) }; var authenticationPassword by remember { mutableStateOf(false) }; var password by remember { mutableStateOf("") }
    val actualLength = if (authenticationPassword) 39 else length
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) { EditorHeader("Генератор", close); Panel { Text("Длина: $actualLength", style = MaterialTheme.typography.titleMedium); Slider(length.toFloat(), { length = it.toInt() }, valueRange = 12f..64f, enabled = !authenticationPassword); SwitchLine("Пароль для аутентификации · 39 символов", authenticationPassword) { authenticationPassword = it }; SwitchLine("Специальные символы", symbols) { symbols = it }; SwitchLine("Без похожих символов", ambiguous) { ambiguous = it } }; Button({ val chars = generator.generate(GeneratorOptions(actualLength, symbols = symbols, excludeAmbiguous = ambiguous)); try { password = String(chars) } finally { chars.fill('\u0000') } }, Modifier.fillMaxWidth()) { Text(if (authenticationPassword) "Создать пароль для аутентификации" else "Создать пароль") }; AnimatedVisibility(password.isNotEmpty(), enter = fadeIn(tween(180)) + slideInHorizontally(tween(220)), exit = fadeOut()) { Panel { Text(password, style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.primary); Spacer(Modifier.height(12.dp)); Button({ save(password, if (authenticationPassword) "Пароль для аутентификации" else "Сгенерированный пароль") { password = "" } }, Modifier.fillMaxWidth()) { Text("Сохранить в заметки") } } } }
}

@Composable private fun <T> EntryList(query: String, setQuery: (String) -> Unit, trash: Boolean, setTrash: (Boolean) -> Unit, entries: List<T>, empty: String, add: String, onAdd: () -> Unit, secondary: String? = null, onSecondary: (() -> Unit)? = null, row: @Composable (T) -> Unit) {
    Column(Modifier.fillMaxSize()) { VaultField(query, setQuery, "Поиск", singleLine = true); Spacer(Modifier.height(12.dp)); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { Pill("Все", !trash) { setTrash(false) }; Pill("Корзина", trash) { setTrash(true) } }; Spacer(Modifier.height(12.dp)); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { Button(onAdd, Modifier.weight(1f)) { Text(add) }; if (secondary != null && onSecondary != null) TextButton(onSecondary, Modifier.weight(1f)) { Text(secondary) } }; Spacer(Modifier.height(12.dp)); if (entries.isEmpty()) Panel { Text(empty, style = MaterialTheme.typography.titleMedium); Text("Добавьте первую запись, чтобы она появилась здесь.", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp)) } else LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) { items(entries, key = { it.hashCode() }) { row(it) } } }
}
@Composable private fun Panel(content: @Composable ColumnScope.() -> Unit) = Card(shape = PanelShape, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) { Column(Modifier.padding(20.dp), content = content) }
@Composable private fun VaultField(value: String, change: (String) -> Unit, label: String, secret: Boolean = false, singleLine: Boolean = false, minLines: Int = 1) = OutlinedTextField(value, change, label = { Text(label) }, singleLine = singleLine, minLines = minLines, visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None, colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = MaterialTheme.colorScheme.primary, focusedLabelColor = MaterialTheme.colorScheme.primary), modifier = Modifier.fillMaxWidth())
@Composable private fun Pill(label: String, selected: Boolean, click: () -> Unit) = Surface(shape = RoundedCornerShape(50), color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.clip(RoundedCornerShape(50)).clickable(onClick = click)) { Text(label, Modifier.padding(horizontal = 16.dp, vertical = 8.dp), color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant) }
@Composable private fun VaultRow(title: String, subtitle: String, click: () -> Unit) = Card(Modifier.fillMaxWidth().clickable(onClick = click), shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) { Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) { Text(title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis); if (subtitle.isNotBlank()) Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis) } }
@Composable private fun EditorHeader(title: String, close: () -> Unit) = Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) { Text(title, Modifier.weight(1f), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold); TextButton(close) { Text("Назад") } }
@Composable private fun SwitchLine(label: String, value: Boolean, change: (Boolean) -> Unit) = Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) { Text(label, Modifier.weight(1f)); Switch(value, change) }
