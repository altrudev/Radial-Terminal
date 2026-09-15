package dev.altru.radialterminal

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.altru.radialterminal.assurance.CommandGate
import dev.altru.radialterminal.assurance.GateResult
import dev.altru.radialterminal.assurance.PreflightRequest
import dev.altru.radialterminal.assurance.SessionMode
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    RadialTerminalScreen()
                }
            }
        }
    }
}

@Composable
private fun RadialTerminalScreen() {
    var mode by remember { mutableStateOf(SessionMode.GUARDED) }
    var command by remember { mutableStateOf("git status") }
    var gateResult by remember { mutableStateOf<GateResult?>(null) }
    var evaluating by remember { mutableStateOf(false) }
    val sessionId = remember { UUID.randomUUID().toString() }
    val gate = remember { CommandGate() }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Text("Radial Terminal", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Assurance-aware SSH operator console",
            style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(Modifier.height(16.dp))

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("DEMO TARGET · NOT VERIFIED", style = MaterialTheme.typography.labelMedium)
                Text("demo-host · SSH :22", style = MaterialTheme.typography.titleMedium)
                Text("Transport is not connected in v0.2.")
                Text(
                    "Session ${sessionId.take(8)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            SessionMode.entries.forEach { candidate ->
                if (candidate == mode) {
                    Button(
                        onClick = {
                            mode = candidate
                            gateResult = null
                        },
                    ) {
                        Text(candidate.name.lowercase().replaceFirstChar(Char::uppercase))
                    }
                } else {
                    OutlinedButton(
                        onClick = {
                            mode = candidate
                            gateResult = null
                        },
                    ) {
                        Text(candidate.name.lowercase().replaceFirstChar(Char::uppercase))
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .background(
                    MaterialTheme.colorScheme.inverseSurface,
                    RoundedCornerShape(12.dp),
                )
                .padding(14.dp),
        ) {
            Column {
                Text(
                    "DEMO TERMINAL · NO COMMANDS EXECUTE",
                    color = MaterialTheme.colorScheme.inverseOnSurface,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "$ git status",
                    color = MaterialTheme.colorScheme.inverseOnSurface,
                )
                Text(
                    "Example output only",
                    color = MaterialTheme.colorScheme.inverseOnSurface,
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = command,
            onValueChange = {
                command = it
                gateResult = null
            },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Command preflight") },
            singleLine = true,
            enabled = !evaluating,
        )

        Spacer(Modifier.height(8.dp))

        Button(
            onClick = {
                evaluating = true
                scope.launch {
                    try {
                        gateResult = gate.evaluate(
                            mode = mode,
                            request = PreflightRequest(
                                sessionId = sessionId,
                                hostId = "demo-host-unverified",
                                command = command,
                                requestedAt = Instant.now(),
                            ),
                        )
                    } finally {
                        evaluating = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !evaluating,
        ) {
            Text(if (evaluating) "Evaluating…" else "Evaluate preflight")
        }

        gateResult?.let {
            Spacer(Modifier.height(10.dp))
            PreflightCard(it)
        }
    }
}

@Composable
private fun PreflightCard(result: GateResult) {
    val decision = when (result) {
        is GateResult.Proceed -> result.decision
        is GateResult.Confirm -> result.decision
        is GateResult.Deny -> result.decision
    }

    val title = when (result) {
        is GateResult.Proceed ->
            if (decision.assuranceBypassed) {
                "DIRECT · assurance intentionally bypassed"
            } else {
                "ALLOW · preflight permits proceeding"
            }
        is GateResult.Confirm -> "REVIEW · confirmation required"
        is GateResult.Deny -> "BLOCK · do not proceed"
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text("Provider: ${decision.provider} ${decision.providerVersion}")
            if (decision.findings.isEmpty()) {
                Text("No classifier findings.")
            } else {
                decision.findings.forEach { finding ->
                    Text("• ${finding.summary}")
                }
            }
        }
    }
}
