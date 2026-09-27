package ir.hyperion.app

/**
 * A deliberately tiny JSON reader, used only by the unit tests to load the
 * cross-language vectors.
 *
 * It exists so the tests can avoid a JSON dependency and so they run as plain
 * JVM tests without android.jar stubs. It supports exactly what
 * `vectors/cross_language.json` contains: objects, arrays, strings, numbers,
 * booleans and null. Anything else throws rather than guessing.
 */
internal object MiniJson {

    fun parse(text: String): Any? = Parser(text).parseValue()

    private class Parser(private val src: String) {
        private var pos = 0

        fun parseValue(): Any? {
            skipWhitespace()
            if (pos >= src.length) throw IllegalArgumentException("unexpected end of input")
            return when (val c = src[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't', 'f' -> parseBoolean()
                'n' -> parseNull()
                else -> if (c == '-' || c.isDigit()) parseNumber()
                else throw IllegalArgumentException("unexpected '$c' at $pos")
            }
        }

        private fun parseObject(): Map<String, Any?> {
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek() == '}') { pos++; return out }
            while (true) {
                skipWhitespace()
                val key = parseString()
                skipWhitespace()
                expect(':')
                out[key] = parseValue()
                skipWhitespace()
                when (val c = src[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> throw IllegalArgumentException("expected , or } but got '$c' at $pos")
                }
            }
        }

        private fun parseArray(): List<Any?> {
            expect('[')
            val out = mutableListOf<Any?>()
            skipWhitespace()
            if (peek() == ']') { pos++; return out }
            while (true) {
                out += parseValue()
                skipWhitespace()
                when (val c = src[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> throw IllegalArgumentException("expected , or ] but got '$c' at $pos")
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (pos < src.length) {
                val c = src[pos]
                if (c == '\\') {
                    val next = src[pos + 1]
                    when (next) {
                        '"', '\\', '/' -> out.append(next)
                        'n' -> out.append('\n')
                        't' -> out.append('\t')
                        'r' -> out.append('\r')
                        'b' -> out.append('\b')
                        'f' -> out.append('\u000C')
                        'u' -> {
                            out.append(src.substring(pos + 2, pos + 6).toInt(16).toChar())
                            pos += 4
                        }
                        else -> throw IllegalArgumentException("bad escape \\$next at $pos")
                    }
                    pos += 2
                    continue
                }
                if (c == '"') { pos++; return out.toString() }
                out.append(c)
                pos++
            }
            throw IllegalArgumentException("unterminated string")
        }

        private fun parseNumber(): Double {
            val start = pos
            if (src[pos] == '-') pos++
            while (pos < src.length && (src[pos].isDigit() || src[pos] in ".eE+-")) pos++
            return src.substring(start, pos).toDouble()
        }

        private fun parseBoolean(): Boolean {
            return if (src.startsWith("true", pos)) { pos += 4; true }
            else if (src.startsWith("false", pos)) { pos += 5; false }
            else throw IllegalArgumentException("bad literal at $pos")
        }

        private fun parseNull(): Any? {
            if (src.startsWith("null", pos)) { pos += 4; return null }
            throw IllegalArgumentException("bad literal at $pos")
        }

        private fun peek(): Char = src[pos]
        private fun expect(c: Char) {
            if (pos >= src.length || src[pos] != c) {
                throw IllegalArgumentException("expected '$c' at $pos")
            }
            pos++
        }
        private fun skipWhitespace() {
            while (pos < src.length && src[pos].isWhitespace()) pos++
        }
    }
}

/** Convenience accessors used by the vector tests. */
@Suppress("UNCHECKED_CAST")
internal fun Any?.asMap(): Map<String, Any?> = this as Map<String, Any?>

@Suppress("UNCHECKED_CAST")
internal fun Any?.asList(): List<Any?> = this as List<Any?>

internal fun Any?.asString(): String = this as String

internal fun Any?.asDouble(): Double = this as Double

internal fun Any?.asInt(): Int = (this as Double).toInt()
