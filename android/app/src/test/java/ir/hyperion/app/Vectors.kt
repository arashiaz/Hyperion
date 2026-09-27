package ir.hyperion.app

import java.io.File

/**
 * Loads `vectors/cross_language.json`, which the Python core generates.
 *
 * Two lookup strategies, because unit tests are not always run from the same
 * working directory: the classpath resource configured in `app/build.gradle.kts`
 * first, then a path relative to the module. If neither resolves, the message
 * says which one to fix rather than failing with a null.
 */
internal object Vectors {

    private const val RESOURCE = "cross_language.json"
    private val RELATIVE_PATHS = listOf(
        "../vectors/$RESOURCE",
        "../../vectors/$RESOURCE",
        "vectors/$RESOURCE",
    )

    val document: Map<String, Any?> by lazy { parse(load()) }

    private fun load(): String {
        javaClass.classLoader.getResourceAsStream(RESOURCE)?.use { stream ->
            return stream.reader(Charsets.UTF_8).readText()
        }
        for (path in RELATIVE_PATHS) {
            val file = File(path)
            if (file.isFile) return file.readText(Charsets.UTF_8)
        }
        throw IllegalStateException(
            "cannot find $RESOURCE: add `$rootDirHint/vectors` to the test source set " +
                "resources, or run Gradle from the repository. Looked on the classpath and at " +
                RELATIVE_PATHS.joinToString(),
        )
    }

    private val rootDirHint get() = "../.."

    private fun parse(text: String): Map<String, Any?> = MiniJson.parse(text).asMap()
}
