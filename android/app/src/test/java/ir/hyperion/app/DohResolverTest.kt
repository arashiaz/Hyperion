package ir.hyperion.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Byte-level agreement with `hyperion/dns.py`, checked against the vectors the
 * Python core generates.
 */
class DohResolverTest {

    private val vectors: Map<String, Any?> get() = Vectors.document

    private val dns: Map<String, Any?> get() = vectors["dns"].asMap()
    private val queries: List<Map<String, Any?>> get() = dns["queries"].asList().map { it.asMap() }

    @Test
    fun `the transaction id constant matches python`() {
        assertEquals(dns["query_id"].asInt(), DohResolver.QUERY_ID)
        assertEquals(0x4859, DohResolver.QUERY_ID)
    }

    @Test
    fun `the sinkhole list matches python`() {
        val expected = dns["known_sinkholes"].asList().map { it.asString() }.toSet()
        assertEquals(expected, DohResolver.KNOWN_SINKHOLES)
        assertTrue(DohResolver.KNOWN_SINKHOLES.contains("10.10.34.35"))
    }

    @Test
    fun `every encoded query is byte identical to the python output`() {
        for (case in queries) {
            val encoded = DohResolver.encodeQuery(case["name"].asString(), case["qtype"].asInt())
            val expectedHex = case["query_hex"].asString()
            assertEquals(
                "query for ${case["name"]} differs from the Python core",
                expectedHex,
                encoded.joinToString("") { "%02x".format(it) },
            )
            assertEquals(case["query_length"].asInt(), encoded.size)
        }
    }

    @Test
    fun `a query has the documented shape`() {
        val query = DohResolver.encodeQuery("example.com")
        // 12-byte header + 13-byte encoded qname (root label included) + 4-byte
        // QTYPE/QCLASS == 29, matching hyperion.dns.encode_query exactly.
        assertEquals(29, query.size)
        assertEquals(0x48, query[0].toInt() and 0xFF)
        assertEquals(0x59, query[1].toInt() and 0xFF)
        assertEquals(0x01, query[2].toInt() and 0xFF) // RD set
        assertEquals(0x00, query[3].toInt() and 0xFF)
        assertEquals(1, query[5].toInt())             // QDCOUNT
        assertEquals(7, query[12].toInt())            // "example" length
        assertEquals(0, query[24].toInt())            // root label
    }

    @Test
    fun `an aaaa query carries qtype 28`() {
        val query = DohResolver.encodeQuery("example.com", DohResolver.QTYPE_AAAA)
        val qtype = ((query[query.size - 4].toInt() and 0xFF) shl 8) or (query[query.size - 3].toInt() and 0xFF)
        assertEquals(28, qtype)
    }

    @Test
    fun `an empty domain is refused`() {
        try {
            DohResolver.encodeQuery("...")
            throw AssertionError("expected an empty name to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("empty domain name"))
        }
    }

    // -- sinkhole analysis -------------------------------------------------

    @Test
    fun `known iranian sinkholes are flagged`() {
        for (sinkhole in DohResolver.KNOWN_SINKHOLES) {
            val reasons = DohResolver.analyse("example.com", listOf(sinkhole))
            assertTrue("$sinkhole was not flagged", reasons.any { it.contains(sinkhole) })
        }
    }

    @Test
    fun `private answers are flagged`() {
        for (ip in listOf("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1")) {
            assertTrue("$ip was not flagged", DohResolver.analyse("example.com", listOf(ip)).isNotEmpty())
        }
    }

    @Test
    fun `a real public answer is clean`() {
        assertEquals(emptyList<String>(), DohResolver.analyse("example.com", listOf("93.184.216.34")))
    }

    @Test
    fun `resolving a dot invalid name proves hijack`() {
        val reasons = DohResolver.analyse("probe.invalid", listOf("5.5.5.5"))
        assertTrue(reasons.any { it.contains(".invalid") })
    }

    // -- DNS response extraction ------------------------------------------

    @Test
    fun `a records are extracted from a wire format response`() {
        val response = buildResponse("example.com", listOf("93.184.216.34", "93.184.215.1"))
        assertEquals(listOf("93.184.216.34", "93.184.215.1"), DiagnosticEngine.extractAddresses(response))
    }

    @Test
    fun `a sinkholed response is detected end to end`() {
        val response = buildResponse("example.com", listOf("10.10.34.35"))
        val addresses = DiagnosticEngine.extractAddresses(response)
        assertTrue(DohResolver.analyse("example.com", addresses).isNotEmpty())
    }

    @Test
    fun `a truncated message yields nothing rather than a guess`() {
        assertEquals(emptyList<String>(), DiagnosticEngine.extractAddresses(ByteArray(5)))
    }

    private fun buildResponse(name: String, ips: List<String>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0x48); out.write(0x59)             // id
        out.write(0x81); out.write(0x80)             // flags: response, no error
        out.write(0); out.write(1)                   // qdcount
        out.write(0); out.write(ips.size)            // ancount
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0)
        out.write(0); out.write(1)                   // qtype A
        out.write(0); out.write(1)                   // qclass IN
        for (ip in ips) {
            out.write(0xC0); out.write(0x0C)         // pointer to the qname
            out.write(0); out.write(1)               // type A
            out.write(0); out.write(1)               // class IN
            out.write(0); out.write(0); out.write(1); out.write(0x2C) // ttl 300
            out.write(0); out.write(4)               // rdlength
            for (octet in ip.split('.')) out.write(octet.toInt())
        }
        return out.toByteArray()
    }
}
