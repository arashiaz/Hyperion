package ir.hyperion.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Cross-language conformance tests.
 *
 * Every expected value here comes from `vectors/cross_language.json`, which the
 * Python core generates (`python3 -m hyperion.tools.gen_vectors`). If the Kotlin
 * implementation drifts from the Python one, these fail in CI rather than in the
 * field.
 */
class TruthGateTest {

    private val vectors: Map<String, Any?> get() = Vectors.document

    private val hmac: Map<String, Any?> get() = vectors["hmac"].asMap()
    private val secret: ByteArray get() = Base64.getDecoder().decode(hmac["secret_b64"].asString())
    private val attestations: List<Map<String, Any?>>
        get() = hmac["attestations"].asList().map { it.asMap() }

    // -- agreement with the Python core -----------------------------------

    @Test
    fun `the canonical string matches the python core`() {
        for (case in attestations) {
            val attestation = TruthGate.Attestation(
                egressIp = case["egress_ip"].asString(),
                ts = case["ts"].asString(),
                nonce = case["nonce"].asString(),
                signature = case["signature"].asString(),
            )
            assertEquals(case["canonical"].asString(), attestation.canonical)
        }
    }

    @Test
    fun `signing the canonical string reproduces the python signature`() {
        val gate = TruthGate.Gate(secret)
        for (case in attestations) {
            val canonical = case["canonical"].asString()
            val expected = case["signature"].asString()
            assertEquals("signature mismatch for $canonical", expected, TruthGate.sign(secret, canonical))
            val attestation = TruthGate.Attestation(
                case["egress_ip"].asString(),
                case["ts"].asString(),
                case["nonce"].asString(),
                expected,
            )
            assertTrue(gate.checkSignature(attestation).passed)
        }
    }

    @Test
    fun `every python attestation parses from its json form`() {
        val gate = TruthGate.Gate(secret)
        for (case in attestations) {
            val parsed = gate.parse(case["json"].asString())
            assertEquals(case["egress_ip"].asString(), parsed.egressIp)
            assertEquals(case["ts"].asString(), parsed.ts)
            assertEquals(case["nonce"].asString(), parsed.nonce)
            assertEquals(case["signature"].asString(), parsed.signature)
        }
    }

    @Test
    fun `the wire timestamp is a string and is never reformatted`() {
        // 1799999999.9995 is a rounding boundary. Signing over the transmitted
        // string means neither side has to agree about float formatting.
        val boundary = attestations.first { it["nonce"].asString() == "x" }
        val gate = TruthGate.Gate(secret)
        val parsed = gate.parse(boundary["json"].asString())
        assertTrue(gate.checkSignature(parsed).passed)
        assertEquals(boundary["canonical"].asString(), parsed.canonical)
    }

    // -- the checks themselves --------------------------------------------

    /**
     * Build an attestation body signed with the test secret.
     *
     * [tamper] is applied *after* signing, so the signature no longer matches the
     * body -- which is exactly the forgery the verifier has to catch.
     */
    private fun body(
        egress: String = "93.184.216.34",
        ts: String = "%.3f".format(TruthGate.now()),
        nonce: String = "nonce-1",
        tamper: ((egress: String, ts: String, nonce: String, signature: String) -> String)? = null,
    ): String {
        val signature = TruthGate.sign(secret, "$egress|$ts|$nonce")
        val json = """{"egress_ip":"$egress","ts":"$ts","nonce":"$nonce",""" +
            """"signature":"$signature","algorithm":"hmac-sha256"}"""
        return tamper?.invoke(egress, ts, nonce, signature) ?: json
    }

    /** Rewrite one field after signing, leaving the original signature in place. */
    private fun forgeEgress(newEgress: String) =
        { egress: String, ts: String, nonce: String, signature: String ->
            """{"egress_ip":"$newEgress","ts":"$ts","nonce":"$nonce",""" +
                """"signature":"$signature","algorithm":"hmac-sha256"}"""
        }

    @Test
    fun `a valid attestation passes every check`() {
        val verdict = TruthGate.Gate(secret).verify(body(), httpStatus = 200)
        assertTrue("failed: ${verdict.failed}", verdict.passed)
        assertEquals(
            listOf("http-status", "signature", "freshness", "egress"),
            verdict.checks.map { it.name },
        )
    }

    @Test
    fun `a forged egress is rejected on the signature`() {
        val verdict = TruthGate.Gate(secret).verify(
            body(tamper = forgeEgress("8.8.8.8")),
            httpStatus = 200,
        )
        assertFalse(verdict.passed)
        assertEquals(listOf("signature"), verdict.failed)
    }

    @Test
    fun `nothing downstream is trusted once the signature fails`() {
        val verdict = TruthGate.Gate(secret).verify(
            body(tamper = forgeEgress("10.0.0.1")),
            httpStatus = 200,
        )
        assertFalse(verdict.checks.any { it.name == "egress" })
    }

    @Test
    fun `the wrong secret is rejected`() {
        val other = TruthGate.Gate(ByteArray(32) { 0x7f })
        assertFalse(other.verify(body(), httpStatus = 200).passed)
    }

    @Test
    fun `an expired attestation is rejected`() {
        val stale = "%.3f".format(TruthGate.now() - 3600)
        val verdict = TruthGate.Gate(secret).verify(body(ts = stale), httpStatus = 200)
        assertTrue(verdict.failed.contains("freshness"))
    }

    @Test
    fun `a future dated attestation is rejected`() {
        val future = "%.3f".format(TruthGate.now() + 3600)
        val verdict = TruthGate.Gate(secret).verify(body(ts = future), httpStatus = 200)
        assertTrue(verdict.failed.contains("freshness"))
    }

    @Test
    fun `a replayed nonce is rejected the second time`() {
        val gate = TruthGate.Gate(secret)
        val payload = body(nonce = "fixed-nonce")
        assertTrue(gate.verify(payload, httpStatus = 200).passed)
        val replay = gate.verify(payload, httpStatus = 200)
        assertFalse(replay.passed)
        assertTrue(replay.failed.contains("freshness"))
    }

    @Test
    fun `a failed check does not consume the nonce`() {
        val gate = TruthGate.Gate(secret)
        assertFalse(gate.verify(body(egress = "10.0.0.1", nonce = "still-free"), httpStatus = 200).passed)
        assertTrue(gate.verify(body(egress = "93.184.216.34", nonce = "still-free"), httpStatus = 200).passed)
    }

    @Test
    fun `a non routable egress fails`() {
        for (ip in listOf("10.0.0.1", "192.168.1.5", "127.0.0.1", "172.16.0.1", "100.64.0.1")) {
            val verdict = TruthGate.Gate(secret).verify(body(egress = ip), httpStatus = 200)
            assertTrue("$ip should not be accepted", verdict.failed.contains("egress"))
        }
    }

    @Test
    fun `a public egress that is our own address fails`() {
        val gate = TruthGate.Gate(secret, localAddresses = setOf("93.184.216.34"))
        assertTrue(gate.verify(body(), httpStatus = 200).failed.contains("egress"))
    }

    @Test
    fun `a bare 204 with no body is not evidence`() {
        // This is the exact check the previous design accepted.
        assertFalse(TruthGate.Gate(secret).verify("", httpStatus = 204).passed)
    }

    @Test
    fun `a 403 from the censor fails`() {
        assertFalse(TruthGate.Gate(secret).verify(body(), httpStatus = 403).failed.isEmpty())
    }

    @Test
    fun `html from a hijack proxy fails to parse`() {
        val verdict = TruthGate.Gate(secret).verify("<html>blocked</html>", httpStatus = 200)
        assertFalse(verdict.passed)
        assertTrue(verdict.failed.contains("attestation"))
    }

    @Test
    fun `an unsupported algorithm is refused`() {
        val json = """{"egress_ip":"93.184.216.34","ts":"1800000000.000","nonce":"n",""" +
            """"signature":"x","algorithm":"md5"}"""
        try {
            TruthGate.Gate(secret).parse(json)
            throw AssertionError("expected the md5 algorithm to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("unsupported algorithm"))
        }
    }

    @Test
    fun `a too short secret is refused at construction`() {
        try {
            TruthGate.Gate(ByteArray(8))
            throw AssertionError("expected a short secret to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("16 bytes"))
        }
    }

    // -- address classification -------------------------------------------

    @Test
    fun `global address classification matches the python verdicts`() {
        for (public in listOf("93.184.216.34", "1.1.1.1", "8.8.8.8", "2001:4860:4860::8888")) {
            assertTrue("$public should be global", TruthGate.isGlobalAddress(public))
        }
        for (blocked in listOf(
            "10.10.34.35", "10.10.34.36", "10.0.0.1", "192.168.0.1", "172.31.255.255",
            "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1",
            "198.51.100.7", "203.0.113.9", "::1", "fe80::1", "fd00::1", "2001:db8::1",
        )) {
            assertFalse("$blocked should not be global", TruthGate.isGlobalAddress(blocked))
        }
    }

    // -- flat JSON reader --------------------------------------------------

    @Test
    fun `the flat json reader handles escapes and rejects non strings`() {
        assertEquals("a\"b", TruthGate.stringField("""{"k":"a\"b"}""", "k"))
        assertEquals("tab\there", TruthGate.stringField("""{"k":"tab\there"}""", "k"))
        assertEquals(null, TruthGate.stringField("""{"k":42}""", "k"))
        assertEquals(null, TruthGate.stringField("""{"other":"x"}""", "k"))
        // A substring of another key must not match.
        assertEquals(null, TruthGate.stringField("""{"my_key":"x"}""", "key"))
    }
}
