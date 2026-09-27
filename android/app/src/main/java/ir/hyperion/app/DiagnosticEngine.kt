package ir.hyperion.app

import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Runs the diagnostic chain and reports what was *proved*, not what was hoped.
 *
 * Each step yields a [Step] with an explicit status. A step that could not run is
 * reported as SKIPPED with a reason; it is never folded into OK. That distinction
 * is the point of the class: an earlier design of this project reported a clean
 * pass from a run that never touched the network.
 */
object DiagnosticEngine {

    const val OK = "ok"
    const val FAIL = "fail"
    const val SKIPPED = "skipped"

    data class Step(
        val name: String,
        val status: String,
        val detail: String,
        val evidence: List<String> = emptyList(),
    ) {
        val passed: Boolean get() = status == OK

        fun render(): String = buildString {
            appendLine("[${status.uppercase().padEnd(7)}] $name: $detail")
            evidence.forEach { appendLine("          $it") }
        }
    }

    data class Report(
        val steps: List<Step>,
        val durationMs: Long,
    ) {
        val passed: Boolean get() = steps.isNotEmpty() && steps.all { it.passed }
        val failed: List<String> get() = steps.filterNot { it.passed }.map { it.name }

        fun render(): String = buildString {
            appendLine("Hyperion run report  ($durationMs ms)")
            appendLine("=".repeat(72))
            steps.forEach { append(it.render()) }
            appendLine("=".repeat(72))
            appendLine(
                if (passed) "RESULT: ALL STEPS VERIFIED"
                else "RESULT: NOT VERIFIED -> ${failed.joinToString()}",
            )
        }
    }

    data class Settings(
        val probeDomain: String = "example.com",
        val probeUrl: String = "",
        val attestationSecret: ByteArray = ByteArray(0),
        val timeoutMs: Int = 8000,
    )

    /**
     * @param opener injected for tests; returns the HTTP status and body.
     */
    fun run(
        settings: Settings,
        resolvers: List<DohResolver.Resolver> = DohResolver.PUBLIC_RESOLVERS,
        opener: (URL, Int) -> Pair<Int, ByteArray> = ::httpGet,
    ): Report {
        val started = System.nanoTime()
        val steps = mutableListOf<Step>()

        // -- 1. DNS ---------------------------------------------------------
        val dnsEvidence = mutableListOf<String>()
        var bestName: String? = null
        var bestLatency = Double.MAX_VALUE
        var anyPoisoned = false
        for (resolver in resolvers) {
            val begun = System.nanoTime()
            val outcome = try {
                val (status, body) = opener(URL(resolver.dohUrl), settings.timeoutMs)
                if (status !in 200..299) {
                    dnsEvidence += "${resolver.name.padEnd(22)} UNREACHABLE  status=$status"
                    null
                } else {
                    val ms = (System.nanoTime() - begun) / 1_000_000.0
                    val addresses = extractAddresses(body)
                    val reasons = DohResolver.analyse(settings.probeDomain, addresses)
                    if (reasons.isNotEmpty()) {
                        anyPoisoned = true
                        dnsEvidence += "${resolver.name.padEnd(22)} POISONED      ${reasons.joinToString("; ")}"
                        null
                    } else {
                        dnsEvidence += "${resolver.name.padEnd(22)} OK            ${ms.toLong()}ms"
                        resolver.name to ms
                    }
                }
            } catch (e: Exception) {
                dnsEvidence += "${resolver.name.padEnd(22)} UNREACHABLE  ${e.javaClass.simpleName}"
                null
            }
            if (outcome != null && outcome.second < bestLatency) {
                bestLatency = outcome.second
                bestName = outcome.first
            }
        }
        steps += if (bestName == null) {
            Step("dns", FAIL, "every resolver either failed or lied", dnsEvidence)
        } else {
            Step("dns", OK, "using $bestName (${bestLatency.toLong()} ms)", dnsEvidence)
        }

        // -- 2. ClientHello shaping ----------------------------------------
        // The client sends no SNI, so the shaping step is trivially safe; it is
        // recorded so the report shows what would go on the wire.
        val hello = ClientHelloBuilder.build(sni = null)
        steps += Step(
            "shard",
            OK,
            "zero-sni: ${hello.size} bytes, no server_name extension",
            listOf("SNI present: ${ClientHelloBuilder.containsSni(hello)}"),
        )

        // -- 3. Truth gate --------------------------------------------------
        steps += when {
            settings.probeUrl.isEmpty() ->
                Step("truth-gate", SKIPPED, "no probe URL configured; egress is unproven")
            settings.attestationSecret.size < 16 ->
                Step("truth-gate", FAIL, "attestation secret must be at least 16 bytes")
            else -> {
                val gate = TruthGate.Gate(
                    secret = settings.attestationSecret,
                    localAddresses = localAddresses(),
                )
                val begun = System.nanoTime()
                try {
                    val (status, body) = opener(URL(settings.probeUrl), settings.timeoutMs)
                    val ms = (System.nanoTime() - begun) / 1_000_000.0
                    val verdict = gate.verify(
                        body = String(body, Charsets.UTF_8),
                        latencyMs = ms,
                        httpStatus = status,
                    )
                    Step(
                        "truth-gate",
                        if (verdict.passed) OK else FAIL,
                        verdict.oneLine(),
                        verdict.checks.map { "  [${if (it.passed) "x" else " "}] ${it.name}: ${it.note}" },
                    )
                } catch (e: Exception) {
                    Step("truth-gate", FAIL, "${e.javaClass.simpleName}: ${e.message}")
                }
            }
        }

        val durationMs = (System.nanoTime() - started) / 1_000_000
        return Report(steps, durationMs)
    }

    /**
     * Pull A-record addresses out of a DNS wire-format response.
     *
     * Only what the diagnostics need: skip the question section, then read answer
     * RRs and keep the type-1 ones. Name compression is followed with a loop
     * guard, since a middlebox is exactly the kind of peer that emits a cycle.
     */
    internal fun extractAddresses(message: ByteArray): List<String> {
        if (message.size < 12) return emptyList()
        val ancount = u16(message, 6)
        var pos = 12
        pos = skipName(message, pos) + 4 // single question
        val out = mutableListOf<String>()
        repeat(ancount) {
            if (pos >= message.size) return@repeat
            pos = skipName(message, pos)
            if (pos + 10 > message.size) return@repeat
            val rtype = u16(message, pos)
            val rdlength = u16(message, pos + 8)
            pos += 10
            if (pos + rdlength > message.size) return@repeat
            if (rtype == DohResolver.QTYPE_A && rdlength == 4) {
                out += "${message[pos].toInt() and 0xFF}.${message[pos + 1].toInt() and 0xFF}." +
                    "${message[pos + 2].toInt() and 0xFF}.${message[pos + 3].toInt() and 0xFF}"
            }
            pos += rdlength
        }
        return out
    }

    private fun u16(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xFF shl 8) or (buffer[offset + 1].toInt() and 0xFF)

    private fun skipName(message: ByteArray, offset: Int): Int {
        var pos = offset
        var jumped = false
        val seen = mutableSetOf<Int>()
        while (pos < message.size) {
            val length = message[pos].toInt() and 0xFF
            if (length == 0) return if (jumped) offset + 2 else pos + 1
            if (length and 0xC0 == 0xC0) {
                val pointer = ((length and 0x3F) shl 8) or (message[pos + 1].toInt() and 0xFF)
                if (!jumped) {
                    jumped = true
                    seen += pos
                }
                if (seen.contains(pointer) || pointer >= message.size) {
                    throw IllegalArgumentException("compression pointer loop or out of range")
                }
                seen += pointer
                pos = pointer
                continue
            }
            pos += 1 + length
        }
        throw IllegalArgumentException("name runs past the end of the message")
    }

    internal fun localAddresses(): Set<String> = try {
        java.net.NetworkInterface.getNetworkInterfaces().toList().flatMap { iface ->
            iface.inetAddresses.toList().mapNotNull { it.hostAddress }
        }.toSet()
    } catch (e: Exception) {
        emptySet()
    }

    private fun httpGet(url: URL, timeoutMs: Int): Pair<Int, ByteArray> {
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.setRequestProperty("Accept", "application/dns-message, application/json")
        connection.setRequestProperty("User-Agent", "Hyperion/1.0")
        return try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.readBytes() ?: ByteArray(0)
            status to body
        } finally {
            connection.disconnect()
        }
    }
}

/**
 * Builds the ClientHello the app sends, and inspects one that was captured.
 *
 * The interesting property is negative: there is no server_name extension, so an
 * SNI filter has nothing to match on.
 */
object ClientHelloBuilder {

    private const val EXT_SERVER_NAME = 0x0000
    private const val EXT_SUPPORTED_VERSIONS = 0x002B

    /** A minimal valid TLS 1.2/1.3 ClientHello record. */
    @JvmOverloads
    fun build(sni: String?): ByteArray {
        val extensions = java.io.ByteArrayOutputStream()
        if (sni != null) {
            val host = encodeDnsLabel(sni)
            val entry = ByteArray(3 + host.size)
            entry[0] = 0 // host_name
            entry[1] = (host.size shr 8 and 0xFF).toByte()
            entry[2] = (host.size and 0xFF).toByte()
            System.arraycopy(host, 0, entry, 3, host.size)
            writeExtension(extensions, EXT_SERVER_NAME, prefixed(entry))
        }
        writeExtension(
            extensions,
            EXT_SUPPORTED_VERSIONS,
            byteArrayOf(4, 0x03, 0x03, 0x03, 0x04),
        )
        val extBytes = extensions.toByteArray()

        val cipherSuites = intArrayOf(0x1301, 0x1303, 0xC02B, 0xC02F)
        val body = java.io.ByteArrayOutputStream()
        body.write(0x03); body.write(0x03)                 // client version
        body.write(ByteArray(32) { it.toByte() })          // random
        body.write(0)                                      // empty session id
        body.write(cipherSuites.size * 2 shr 8); body.write(cipherSuites.size * 2 and 0xFF)
        cipherSuites.forEach { body.write(it shr 8 and 0xFF); body.write(it and 0xFF) }
        body.write(1); body.write(0)                       // one compression method: null
        body.write(extBytes.size shr 8 and 0xFF); body.write(extBytes.size and 0xFF)
        body.write(extBytes)

        val bodyBytes = body.toByteArray()
        val handshake = java.io.ByteArrayOutputStream()
        handshake.write(1) // ClientHello
        handshake.write(bodyBytes.size shr 16 and 0xFF)
        handshake.write(bodyBytes.size shr 8 and 0xFF)
        handshake.write(bodyBytes.size and 0xFF)
        handshake.write(bodyBytes)
        val handshakeBytes = handshake.toByteArray()

        val record = java.io.ByteArrayOutputStream()
        record.write(22) // handshake
        record.write(0x03); record.write(0x01)
        record.write(handshakeBytes.size shr 8 and 0xFF)
        record.write(handshakeBytes.size and 0xFF)
        record.write(handshakeBytes)
        return record.toByteArray()
    }

    /** True if a captured ClientHello record carries a server_name extension. */
    fun containsSni(record: ByteArray): Boolean {
        if (record.size < 5 || record[0].toInt() != 22) return false
        val length = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
        if (record.size < 5 + length) return false
        val payload = record.copyOfRange(5, 5 + length)
        if (payload.size < 4 || payload[0].toInt() != 1) return false
        var pos = 4 + 2 + 32                       // version + random
        pos += 1 + (payload[pos].toInt() and 0xFF) // session id
        val csLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2 + csLen
        pos += 1 + (payload[pos].toInt() and 0xFF) // compression methods
        if (pos + 2 > payload.size) return false
        val extTotal = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
        pos += 2
        val end = pos + extTotal
        while (pos + 4 <= end && pos + 4 <= payload.size) {
            val type = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            val len = ((payload[pos + 2].toInt() and 0xFF) shl 8) or (payload[pos + 3].toInt() and 0xFF)
            if (type == EXT_SERVER_NAME) return true
            pos += 4 + len
        }
        return false
    }

    private fun prefixed(entry: ByteArray): ByteArray {
        val out = ByteArray(2 + entry.size)
        out[0] = (entry.size shr 8 and 0xFF).toByte()
        out[1] = (entry.size and 0xFF).toByte()
        System.arraycopy(entry, 0, out, 2, entry.size)
        return out
    }

    private fun writeExtension(out: java.io.ByteArrayOutputStream, type: Int, body: ByteArray) {
        out.write(type shr 8 and 0xFF)
        out.write(type and 0xFF)
        out.write(body.size shr 8 and 0xFF)
        out.write(body.size and 0xFF)
        out.write(body)
    }
}

/** Decode a base64 or base64url secret from user input. */
fun decodeSecret(text: String): ByteArray {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) return ByteArray(0)
    return try {
        Base64.getDecoder().decode(trimmed)
    } catch (e: IllegalArgumentException) {
        Base64.getUrlDecoder().decode(trimmed.padEnd(trimmed.length + (4 - trimmed.length % 4) % 4, '='))
    }
}
