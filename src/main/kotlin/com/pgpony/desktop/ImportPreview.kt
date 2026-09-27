// ImportPreview.kt
// PGPony Desktop 3.0.0, stage 3 checkpoint 3d (plan 6.5 and 6.6).
//
// ImportPreviewDialog shows what a paste, a QR code or a link holds before anything is written:
// every key's User IDs, fingerprint and algorithm, whether it carries private material, whether
// it is already in the keyring, and where it came from. Surrounding text around the armor is
// ignored (Android 4.5.0 item 19). For a single public key it also offers "Encrypt to this key"
// (Android 4.5.0 item 29): the key is imported and Crypto opens with it as the recipient.
//
// ImportLinkDialog is Android 4.6.0 item 2: fetch a public key from an https link (http only for
// a .onion address) through the vendored UrlKeyFetcher on the desktop HTTP client, so the proxy,
// Tor stream isolation and offline mode all apply. Only public key material comes back, and it
// goes to the preview with the final link shown; nothing is stored until Import.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.network.UrlKeyFetcher
import kotlinx.coroutines.launch

@Composable
fun ImportPreviewDialog(state: DesktopState, armored: String, sourceLink: String?, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var items by remember { mutableStateOf<List<DesktopKeyRepository.ImportPreviewItem>?>(null) }
    var working by remember { mutableStateOf(false) }

    LaunchedEffect(armored) {
        items = state.repository.previewArmoredText(armored)
    }
    val list = items
    val single = list?.singleOrNull()

    fun import(then: (() -> Unit)? = null) {
        working = true
        scope.launch {
            try {
                state.importArmoredTextNow(armored)
                then?.invoke()
            } finally {
                working = false
                onDismiss()
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("d_import_preview_title"),
        content = {
            Column(Modifier.fillMaxWidth().heightIn(max = 480.dp).verticalScroll(rememberScrollState())) {
                sourceLink?.let {
                    Text(
                        tr("import_preview_source_url_format", it),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(8.dp))
                }
                when {
                    list == null -> Text(tr("d_common_working"), style = MaterialTheme.typography.bodyMedium)
                    list.isEmpty() -> Text(tr("d_import_preview_none"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    else -> list.forEach { item -> PreviewCard(item) }
                }
            }
        },
        confirmButton = {
            if (!list.isNullOrEmpty()) {
                TextButton(enabled = !working, onClick = { import() }) {
                    Text(if (working) tr("d_common_working") else tr("import_button_import_key"))
                }
            }
        },
        dismissButton = {
            Row {
                // Android 4.5.0 item 29: a shared public key is often shared to be written to.
                if (single != null && !single.hasPrivateKey) {
                    TextButton(enabled = !working, onClick = {
                        import { state.openCrypto(CryptoPreset(encryptTo = single.fingerprint)) }
                    }) { Text(tr("import_button_encrypt_to_key")) }
                }
                TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) }
            }
        }
    )
}

@Composable
private fun PreviewCard(item: DesktopKeyRepository.ImportPreviewItem) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(10.dp)) {
            if (item.userIds.isEmpty() || item.userIds.all { it.isBlank() }) {
                Text(tr("import_preview_detail_user_empty"), style = MaterialTheme.typography.titleSmall)
            }
            item.userIds.filter { it.isNotBlank() }.forEach { Text(it, style = MaterialTheme.typography.titleSmall) }
            Text(
                item.fingerprint.uppercase().chunked(4).joinToString(" "),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Text(
                tr("d_import_preview_meta", item.algorithmName,
                    if (item.hasPrivateKey) tr("import_preview_type_key_pair") else tr("import_preview_type_public_only")),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (item.inKeyring) {
                Text(tr("d_import_preview_in_keyring"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun ImportLinkDialog(onDismiss: () -> Unit, onFetched: (armored: String, finalUrl: String) -> Unit) {
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf("") }
    var fetching by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val allowed = UrlKeyFetcher.allowedUri(link.trim()) != null

    fun fetch() {
        fetching = true
        error = null
        scope.launch {
            try {
                when (val r = UrlKeyFetcher.fetch(link.trim())) {
                    is UrlKeyFetcher.Result.Keys -> onFetched(r.armored, r.finalUrl)
                    UrlKeyFetcher.Result.NotHttps -> error = tr("import_url_error_https")
                    UrlKeyFetcher.Result.Offline -> error = tr("import_url_error_offline")
                    UrlKeyFetcher.Result.NoKey -> error = tr("import_url_error_no_key")
                    UrlKeyFetcher.Result.TooManyRedirects -> error = tr("import_url_error_redirects")
                    is UrlKeyFetcher.Result.HttpError -> error = tr("import_url_error_http_format", r.status)
                    is UrlKeyFetcher.Result.Failed -> error = tr("import_url_error_failed_format", r.message)
                }
            } catch (t: Throwable) {
                error = tr("import_url_error_failed_format", t.message ?: t::class.simpleName.orEmpty())
            } finally {
                fetching = false
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!fetching) onDismiss() },
        title = tr("d_import_link_title"),
        content = {
            Column {
                OutlinedTextField(
                    value = link, onValueChange = { link = it }, singleLine = true, enabled = !fetching,
                    isError = link.isNotBlank() && !allowed,
                    label = { Text(tr("import_url_label")) }, modifier = Modifier.fillMaxWidth()
                )
                if (link.isNotBlank() && !allowed) {
                    Text(tr("import_url_error_https"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Spacer(Modifier.height(8.dp))
                Text(tr("import_url_help"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = allowed && !fetching, onClick = { fetch() }) {
                Text(if (fetching) tr("d_common_working") else tr("import_url_fetch_button"))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !fetching) { Text(tr("common_button_cancel")) } }
    )
}
