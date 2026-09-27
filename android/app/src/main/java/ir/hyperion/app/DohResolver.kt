package ir.hyperion.app

import java.net.IDN

/**
 * DNS over HTTPS (RFC 8484) query building plus Iranian fake-DNS detection.
 *
 * Port of `hyperion/dns.py`. Byte-level agreement with the Python core is checked
 * in `DohResolverTest` against `vectors/cross_language.json`, so a change on one
 * side that is not mirrored on the other fails CI rather than silently breaking
 * name resolution for users.
 */
object DohResolver {

    /** Transaction id stamped on every query, so a forged reply is detectable. */
    const val QUERY_ID = 0x4859 // "HY"
    const val QTYPE_A = 1
    const val QTYPE_AAAA = 28

    const val DNS_MESSAGE_MEDIA_TYPE = "application/dns-message"
    const val DNS_JSON_MEDIA_TYPE = "application/dns-json"

    /**
     * Sinkhole addresses Iranian operators inject for blocked domains. These sit
     * in RFC 6598 carrier-grade NAT space and are never a legitimate answer for a
     * public name.
     */
    val KNOWN_SINKHOLES: Set<String> = setOf("10.10.34.35", "10.10.34.36")

    data class Resolver(
        val name: String,
        val address: String,
        val dohUrl: String,
        val jsonUrl: String? = null,
    )

    val PUBLIC_RESOLVERS: List<Resolver> = listOf(
        Resolver("cloudflare", "1.1.1.1", "https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"),
        Resolver("cloudflare-secondary", "1.0.0.1", "https://1.0.0.1/dns-query", "https://1.0.0.1/dns-query"),
        Resolver("google", "8.8.8.8", "https://dns.google/dns-query", "https://dns.google/resolve"),
        Resolver("quad9", "9.9.9.9", "https://dns.quad9.net/dns-query", "https://dns.quad9.net/resolve"),
    )

    /**
     * Build a minimal DNS query message.
     *
     * Produces byte-for-byte the same output as `hyperion.dns.encode_query`.
     */
    @JvmOverloads
    fun encodeQuery(name: String, qtype: Int = QTYPE_A, rd: Boolean = true, qid: Int = QUERY_ID): ByteArray {
        val labels = name.trimEnd('.').split('.').filter { it.isNotEmpty() }
        require(labels.isNotEmpty()) { "empty domain name" }

        val out = ByteArray(12)
        putU16(out, 0, qid)
        putU16(out, 2, if (rd) 0x0100 else 0x0000)
        putU16(out, 4, 1) // QDCOUNT
        putU16(out, 6, 0)
        putU16(out, 8, 0)
        putU16(out, 10, 0)

        val body = java.io.ByteArrayOutputStream()
        for (label in labels) {
            val encoded = encodeDnsLabel(label)
            require(encoded.size in 1..63) { "label '$label' is not 1-63 bytes after IDNA" }
            body.write(encoded.size)
            body.write(encoded)
        }
        body.write(0) // root label
        body.write(qtype shr 8 and 0xFF)
        body.write(qtype and 0xFF)
        body.write(0) // QCLASS IN, high byte
        body.write(1) // QCLASS IN, low byte

        return out + body.toByteArray()
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value shr 8 and 0xFF).toByte()
        target[offset + 1] = (value and 0xFF).toByte()
    }

    /**
     * Decide whether a set of answers looks injected rather than authoritative.
     * Returns the reasons; an empty list means the answers look legitimate.
     */
    fun analyse(name: String, addresses: List<String>): List<String> {
        val reasons = mutableListOf<String>()
        for (address in addresses) {
            if (KNOWN_SINKHOLES.contains(address)) {
                reasons += "known Iranian sinkhole $address"
                continue
            }
            if (!TruthGate.isGlobalAddress(address)) {
                reasons += "non-routable answer $address"
            }
        }
        if (name.endsWith(".invalid") && addresses.isNotEmpty()) {
            reasons += "resolved a name under .invalid, which must be NXDOMAIN"
        }
        return reasons
    }
}

/**
 * Encode a domain label, applying IDNA to anything non-ASCII.
 *
 * Note that Java's [IDN.toASCII] and Python's `str.encode("idna")` both implement
 * IDNA2003, but they are not guaranteed to agree on every input, so the shared
 * test vectors use ASCII and pre-encoded Punycode names only.
 */
internal fun encodeDnsLabel(label: String): ByteArray =
    if (label.all { it.code < 128 }) {
        label.toByteArray(Charsets.US_ASCII)
    } else {
        IDN.toASCII(label, IDN.ALLOW_UNASSIGNED).toByteArray(Charsets.US_ASCII)
    }
