package ir.hyperion.app

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Client half of the Truth Gate protocol.
 *
 * This is a port of `hyperion/truth_gate.py` and the two must stay in sync. The
 * wire format is deliberately tiny so that agreement can be *proved* rather than
 * assumed: `app/src/test/java/.../TruthGateTest.kt` checks this implementation
 * against signatures produced by the Python core, from
 * `vectors/cross_language.json`.
 *
 * Why a signature at all: a plain "HTTP 204 means we are free" check is worth
 * nothing, because a middlebox can synthesise a 204 without a byte leaving the
 * country. An HMAC over a secret only the exit server holds cannot be forged,
 * and the nonce stops a captured attestation being replayed.
 */
object TruthGate {

    const val ALGORITHM = "hmac-sha256"
    const val DEFAULT_WINDOW_SECONDS = 30.0

    /** A signed statement by the exit server about what it saw. */
    data class Attestation(
        val egressIp: String,
        /** Timestamp exactly as it appeared on the wire; never re-formatted. */
        val ts: String,
        val nonce: String,
        val signature: String,
        val algorithm: String = ALGORITHM,
    ) {
        /** The exact string that is signed. Field order is part of the protocol. */
        val canonical: String
            get() = "$egressIp|$ts|$nonce"

        val timestampSeconds: Double
            get() = ts.toDoubleOrNull()
                ?: throw IllegalArgumentException("timestamp '$ts' is not a number")
    }

    data class Check(val name: String, val passed: Boolean, val note: String)

    data class Verdict(
        val passed: Boolean,
        val checks: List<Check>,
        val httpStatus: Int?,
        val latencyMs: Double,
    ) {
        val failed: List<String> get() = checks.filterNot { it.passed }.map { it.name }

        fun oneLine(): String = when {
            passed -> "truth-gate: PASS in ${latencyMs.toLong()}ms"
            else -> "truth-gate: FAIL (${failed.joinToString()}) in ${latencyMs.toLong()}ms"
        }
    }

    /**
     * Verifies attestations. Holds replay state, so use one instance per session.
     */
    class Gate(
        private val secret: ByteArray,
        private val windowSeconds: Double = DEFAULT_WINDOW_SECONDS,
        private val localAddresses: Set<String> = emptySet(),
    ) {
        private val seenNonces = mutableSetOf<String>()

        init {
            require(secret.size >= 16) { "attestation secret must be at least 16 bytes" }
        }

        // -- parsing -------------------------------------------------------

        /**
         * Parse the flat JSON attestation body.
         *
         * A hand-rolled reader rather than org.json: the format is a fixed flat
         * object of strings, and keeping it in plain JVM code means it runs in a
         * unit test without android.jar stubs.
         */
        fun parse(body: String): Attestation {
            val egress = stringField(body, "egress_ip")
                ?: throw IllegalArgumentException("attestation has no egress_ip")
            val ts = stringField(body, "ts")
                ?: throw IllegalArgumentException("attestation has no ts")
            val nonce = stringField(body, "nonce")
                ?: throw IllegalArgumentException("attestation has no nonce")
            val signature = stringField(body, "signature")
                ?: throw IllegalArgumentException("attestation has no signature")
            val algorithm = stringField(body, "algorithm") ?: ALGORITHM
            if (algorithm != ALGORITHM) {
                throw IllegalArgumentException("unsupported algorithm '$algorithm'")
            }
            return Attestation(egress, ts, nonce, signature, algorithm)
        }

        // -- the checks ----------------------------------------------------

        fun checkSignature(attestation: Attestation): Check {
            val expected = sign(secret, attestation.canonical)
            val ok = MessageDigest.isEqual(
                expected.toByteArray(Charsets.UTF_8),
                attestation.signature.toByteArray(Charsets.UTF_8),
            )
            return Check(
                "signature",
                ok,
                if (ok) "signature matches" else "signature does not match (forged or replayed body)",
            )
        }

        fun checkFreshness(attestation: Attestation, nowSeconds: Double = now()): Check {
            val age = nowSeconds - attestation.timestampSeconds
            return when {
                age > windowSeconds ->
                    Check("freshness", false, "attestation is ${fmt(age)}s old, window is ${windowSeconds.toLong()}s")
                age < -windowSeconds ->
                    Check("freshness", false, "attestation is dated ${fmt(-age)}s in the future")
                seenNonces.contains(attestation.nonce) ->
                    Check("freshness", false, "nonce was already accepted (replay)")
                else ->
                    Check("freshness", true, "fresh, ${fmt(age)}s old, nonce unseen")
            }
        }

        fun checkEgress(attestation: Attestation): Check {
            val ip = attestation.egressIp
            if (!isGlobalAddress(ip)) {
                return Check("egress", false, "egress $ip is not globally routable")
            }
            if (localAddresses.contains(ip)) {
                return Check("egress", false, "egress $ip is one of our own local addresses")
            }
            return Check("egress", true, "egress $ip is a public address we do not own")
        }

        /**
         * Run every check. Order matters: the signature gates the rest, because a
         * forger controls every other field.
         */
        @JvmOverloads
        fun verify(
            body: String,
            nowSeconds: Double = now(),
            latencyMs: Double = 0.0,
            httpStatus: Int? = null,
            commitNonce: Boolean = true,
        ): Verdict {
            val statusOk = httpStatus == null || httpStatus in 200..299
            val checks = mutableListOf(Check("http-status", statusOk, "status=$httpStatus"))

            val attestation = try {
                parse(body)
            } catch (e: IllegalArgumentException) {
                checks += Check("attestation", false, e.message ?: "unparseable")
                return Verdict(false, checks, httpStatus, latencyMs)
            }

            val signature = checkSignature(attestation)
            checks += signature
            if (!signature.passed) {
                return Verdict(false, checks, httpStatus, latencyMs)
            }

            checks += checkFreshness(attestation, nowSeconds)
            checks += checkEgress(attestation)

            val passed = checks.all { it.passed }
            if (passed && commitNonce) {
                seenNonces += attestation.nonce
            }
            return Verdict(passed, checks, httpStatus, latencyMs)
        }
    }

    // -- signing -----------------------------------------------------------

    /** HMAC-SHA256 over [message], base64url without padding (as the server sends it). */
    fun sign(secret: ByteArray, message: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        val digest = mac.doFinal(message.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun now(): Double = System.currentTimeMillis() / 1000.0

    /** Locale-independent one-decimal rendering, so report text is stable. */
    private fun fmt(value: Double): String =
        String.format(java.util.Locale.ROOT, "%.1f", value)

    /**
     * True for an address that is routable on the public internet.
     *
     * Mirrors Python's `ipaddress.is_global` closely enough for this check: the
     * cases that matter are the RFC 1918 sinkholes, loopback, link-local and the
     * carrier-grade NAT range that Iranian operators actually inject.
     */
    fun isGlobalAddress(text: String): Boolean {
        val parts = text.split('.')
        if (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) {
            val a = parts[0].toInt()
            val b = parts[1].toInt()
            return when {
                a == 0 -> false                       // 0.0.0.0/8
                a == 10 -> false                        // RFC 1918
                a == 127 -> false                       // loopback
                a == 169 && b == 254 -> false           // link-local
                a == 172 && b in 16..31 -> false        // RFC 1918
                a == 192 && b == 168 -> false           // RFC 1918
                a == 100 && b in 64..127 -> false       // RFC 6598 carrier-grade NAT
                a == 192 && b == 0 -> false             // IETF protocol assignments
                a == 198 && b in 18..19 -> false        // benchmarking
                a == 198 && b == 51 && parts[2].toInt() == 100 -> false // TEST-NET-2
                a == 203 && b == 0 && parts[2].toInt() == 113 -> false  // TEST-NET-3
                a == 224 || a >= 240 -> false           // multicast / reserved
                else -> true
            }
        }
        if (text.contains(':')) {
            val lower = text.lowercase()
            if (lower.startsWith("fc") || lower.startsWith("fd")) return false // unique local
            if (lower.startsWith("fe80")) return false                         // link-local
            if (lower == "::" || lower == "::1") return false                  // unspecified/loopback
            if (lower.startsWith("2001:db8")) return false                     // documentation
            if (lower.startsWith("ff")) return false                           // multicast
            return true
        }
        return false
    }

    // -- minimal flat-JSON reader -----------------------------------------

    /**
     * Extract a string-valued field from a flat JSON object. Returns null if the
     * key is absent or its value is not a JSON string.
     */
    internal fun stringField(json: String, key: String): String? {
        val needle = "\"$key\""
        var search = 0
        while (true) {
            val at = json.indexOf(needle, search)
            if (at < 0) return null
            var i = at + needle.length
            while (i < json.length && json[i].isWhitespace()) i++
            if (i < json.length && json[i] == ':') {
                i++
                while (i < json.length && json[i].isWhitespace()) i++
                if (i < json.length && json[i] == '"') {
                    return readQuoted(json, i)
                }
                return null // present but not a string
            }
            search = at + needle.length
        }
    }

    private fun readQuoted(json: String, openQuote: Int): String {
        val out = StringBuilder()
        var i = openQuote + 1
        while (i < json.length) {
            val c = json[i]
            if (c == '\\' && i + 1 < json.length) {
                val next = json[i + 1]
                when (next) {
                    '"', '\\', '/' -> out.append(next)
                    'n' -> out.append('\n')
                    't' -> out.append('\t')
                    'r' -> out.append('\r')
                    'b' -> out.append('\b')
                    'f' -> out.append('\u000C')
                    else -> out.append(next)
                }
                i += 2
                continue
            }
            if (c == '"') return out.toString()
            out.append(c)
            i++
        }
        throw IllegalArgumentException("unterminated JSON string")
    }
}
