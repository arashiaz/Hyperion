package ir.hyperion.app

/**
 * AmneziaWG obfuscation configuration: parse, validate, render.
 *
 * Port of the configuration half of `hyperion/amneziawg.py`. The key names come
 * from upstream (`amnezia-vpn/amneziawg-go` `device/uapi.go` for the `jc/jmin/
 * jmax/s1..s4/h1..h4/i1..i5` uapi keys, and `amnezia-vpn/amnezia-client`
 * `client/server_scripts/awg/template.conf` for the `.conf` spelling).
 *
 * Deliberately absent: default magic header values. Upstream chooses them per
 * deployment, so a hard-coded default here would silently fail against every real
 * server. An unset `H1` keeps the stock WireGuard type byte, which is correct.
 */
object AmneziaConfig {

    const val STOCK_HANDSHAKE_INITIATION = 1
    const val STOCK_HANDSHAKE_RESPONSE = 2
    const val STOCK_HANDSHAKE_COOKIE_REPLY = 3
    const val STOCK_TRANSPORT_DATA = 4

    val OBF_TAGS = setOf("b", "t", "r", "rc", "rd", "d", "ds", "dz")

    class ConfigError(message: String) : IllegalArgumentException(message)

    /** A value that is either a single number or an inclusive `lo-hi` range. */
    data class UintRange(val lo: Long, val hi: Long) {
        init {
            if (hi < lo) throw ConfigError("range $lo-$hi is inverted")
            if (lo < 0 || hi > 0xFFFFFFFFL) throw ConfigError("$lo-$hi does not fit in uint32")
        }

        override fun toString(): String = if (lo == hi) lo.toString() else "$lo-$hi"

        companion object {
            fun parse(text: String): UintRange {
                val trimmed = text.trim()
                return if (trimmed.contains('-')) {
                    val (loText, hiText) = trimmed.split('-', limit = 2)
                    UintRange(parseMaybeHex(loText), parseMaybeHex(hiText))
                } else {
                    val value = parseMaybeHex(trimmed)
                    UintRange(value, value)
                }
            }
        }
    }

    private fun parseMaybeHex(text: String): Long {
        val trimmed = text.trim()
        require(trimmed.isNotEmpty()) { "empty numeric value" }
        if (trimmed.startsWith("0x", ignoreCase = true)) {
            return trimmed.substring(2).toLong(16)
        }
        val looksHex = trimmed.all { it in "0123456789abcdefABCDEF" } &&
            trimmed.any { it in "abcdefABCDEF" }
        return if (looksHex) trimmed.toLong(16) else trimmed.toLong()
    }

    data class Config(
        val jc: Int = 0,
        val jmin: Int = 0,
        val jmax: Int = 0,
        val s1: Int = 0,
        val s2: Int = 0,
        val s3: Int = 0,
        val s4: Int = 0,
        val h1: UintRange? = null,
        val h2: UintRange? = null,
        val h3: UintRange? = null,
        val h4: UintRange? = null,
        val i1: String = "",
        val i2: String = "",
        val i3: String = "",
        val i4: String = "",
        val i5: String = "",
        val headerProtectionKey: String = "",
        val randomTrailers: Boolean = false,
        val disableCookies: Boolean = false,
        val privateKey: String = "",
        val address: List<String> = emptyList(),
        val dns: List<String> = emptyList(),
        val endpoint: String = "",
        val publicKey: String = "",
    ) {
        init {
            if (jc != 0 && (jmin == 0 || jmax == 0)) {
                throw ConfigError("jc is set but jmin/jmax are not; junk size is undefined")
            }
            if (jmin > jmax) throw ConfigError("jmin $jmin exceeds jmax $jmax")
            if (jmin != 0 && jc == 0) {
                throw ConfigError("jmin is set but jc is 0; no junk packets would be sent")
            }
            for ((name, value) in listOf("s1" to s1, "s2" to s2, "s3" to s3, "s4" to s4)) {
                if (value < 0) throw ConfigError("$name cannot be negative")
            }
            if (headerProtectionKey.isNotEmpty() && headerProtectionKey.length < 32) {
                throw ConfigError("header protection key looks too short to be a 32-byte key")
            }
            for ((name, spec) in listOf(
                "i1" to i1, "i2" to i2, "i3" to i3, "i4" to i4, "i5" to i5,
            )) {
                parseObfSpec(spec).also { tags ->
                    if (tags.isEmpty() && spec.isNotBlank()) {
                        throw ConfigError("$name has content but no <tag> was parsed")
                    }
                }
            }
        }

        /** Render as uapi `key=value` lines, omitting defaults as upstream does. */
        fun toUapi(): String = buildString {
            if (jc != 0) appendLine("jc=$jc")
            if (jmin != 0) appendLine("jmin=$jmin")
            if (jmax != 0) appendLine("jmax=$jmax")
            if (s1 != 0) appendLine("s1=$s1")
            if (s2 != 0) appendLine("s2=$s2")
            if (s3 != 0) appendLine("s3=$s3")
            if (s4 != 0) appendLine("s4=$s4")
            h1?.let { appendLine("h1=$it") }
            h2?.let { appendLine("h2=$it") }
            h3?.let { appendLine("h3=$it") }
            h4?.let { appendLine("h4=$it") }
            if (i1.isNotEmpty()) appendLine("i1=$i1")
            if (i2.isNotEmpty()) appendLine("i2=$i2")
            if (i3.isNotEmpty()) appendLine("i3=$i3")
            if (i4.isNotEmpty()) appendLine("i4=$i4")
            if (i5.isNotEmpty()) appendLine("i5=$i5")
            if (headerProtectionKey.isNotEmpty()) appendLine("header_protection_key=$headerProtectionKey")
            if (randomTrailers) appendLine("random_trailers=true")
            if (disableCookies) appendLine("disable_cookies=true")
        }

        fun describe(): String =
            "jc=$jc jmin=$jmin jmax=$jmax s1=$s1 s2=$s2 s3=$s3 s4=$s4 " +
                "h1=$h1 h2=$h2 h3=$h3 h4=$h4"
    }

    /**
     * Parse an AmneziaWG `.conf`. Key matching is case-insensitive, as the real
     * tooling accepts `Jc` and `jc` alike.
     */
    fun fromConf(text: String): Config {
        val values = mutableMapOf<String, String>()
        var inInterface = false
        var sawInterface = false
        for (rawLine in text.split('\n')) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            if (line.startsWith("[")) {
                inInterface = line.equals("[Interface]", ignoreCase = true)
                if (inInterface) sawInterface = true
                continue
            }
            if (!inInterface) continue
            val equals = line.indexOf('=')
            if (equals <= 0) continue
            values[line.substring(0, equals).trim().lowercase()] = line.substring(equals + 1).trim()
        }
        if (!sawInterface) throw ConfigError("config has no [Interface] section")

        fun num(key: String): Int = values[key]?.takeIf { it.isNotEmpty() }?.toIntOrNull() ?: 0
        fun range(key: String): UintRange? = values[key]?.takeIf { it.isNotEmpty() }?.let { UintRange.parse(it) }
        fun list(key: String): List<String> =
            values[key]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
        fun bool(key: String): Boolean = values[key]?.lowercase() in setOf("1", "true")

        return Config(
            jc = num("jc"),
            jmin = num("jmin"),
            jmax = num("jmax"),
            s1 = num("s1"),
            s2 = num("s2"),
            s3 = num("s3"),
            s4 = num("s4"),
            h1 = range("h1"),
            h2 = range("h2"),
            h3 = range("h3"),
            h4 = range("h4"),
            i1 = values["i1"] ?: "",
            i2 = values["i2"] ?: "",
            i3 = values["i3"] ?: "",
            i4 = values["i4"] ?: "",
            i5 = values["i5"] ?: "",
            headerProtectionKey = values["headerprotectionkey"] ?: "",
            randomTrailers = bool("randomtrailers"),
            disableCookies = bool("disablecookies"),
            privateKey = values["privatekey"] ?: "",
            address = list("address"),
            dns = list("dns"),
            endpoint = values["endpoint"] ?: "",
            publicKey = values["publickey"] ?: "",
        )
    }

    /** Parse an `i1`-style obfuscation spec such as `<b 0xdead><r 8><d>`. */
    fun parseObfSpec(spec: String): List<Pair<String, String>> {
        if (spec.isBlank()) return emptyList()
        val out = mutableListOf<Pair<String, String>>()
        var remaining = spec
        while (true) {
            val start = remaining.indexOf('<')
            if (start < 0) break
            val end = remaining.indexOf('>', start)
            if (end < 0) throw ConfigError("missing closing '>' in obfuscation spec '$spec'")
            val parts = remaining.substring(start + 1, end).trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (parts.isEmpty()) throw ConfigError("empty tag in obfuscation spec '$spec'")
            val key = parts[0]
            if (!OBF_TAGS.contains(key)) throw ConfigError("unknown obfuscation tag <$key>")
            out += key to (parts.getOrElse(1) { "" })
            remaining = remaining.substring(end + 1)
        }
        return out
    }
}
