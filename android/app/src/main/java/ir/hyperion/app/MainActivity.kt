package ir.hyperion.app

import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.util.concurrent.Executors

/**
 * Runs the diagnostic chain on a background thread and prints exactly what each
 * step proved.
 *
 * The screen is deliberately text-only. It is a measurement tool, not a
 * one-button "you are now private" switch: the value is in reading which step
 * failed and why.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var output: TextView
    private lateinit var probeUrl: EditText
    private lateinit var secret: EditText
    private val executor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        output = findViewById(R.id.output)
        output.movementMethod = ScrollingMovementMethod.getInstance()
        probeUrl = findViewById(R.id.probe_url)
        secret = findViewById(R.id.secret)

        findViewById<Button>(R.id.run_diagnostics).setOnClickListener { runDiagnostics() }
        findViewById<Button>(R.id.run_dry).setOnClickListener { runDry() }

        output.text = getString(R.string.intro)
    }

    private fun runDiagnostics() {
        val url = probeUrl.text.toString().trim()
        val key = decodeSecret(secret.text.toString())
        output.text = getString(R.string.running)
        executor.execute {
            val report = DiagnosticEngine.run(
                DiagnosticEngine.Settings(probeUrl = url, attestationSecret = key),
            )
            runOnUiThread { output.text = report.render() }
        }
    }

    /**
     * The offline half only. It must not claim success: steps that were not run
     * are reported as skipped, which is why this prints NOT VERIFIED.
     */
    private fun runDry() {
        output.text = getString(R.string.running)
        executor.execute {
            val hello = ClientHelloBuilder.build(sni = null)
            val lines = listOf(
                "Hyperion offline check",
                "=".repeat(72),
                "[OK     ] shard: zero-sni ClientHello, ${hello.size} bytes",
                "          SNI present: ${ClientHelloBuilder.containsSni(hello)}",
                "[SKIPPED] dns: no resolver was contacted",
                "[SKIPPED] truth-gate: no attestation was requested",
                "=".repeat(72),
                "RESULT: NOT VERIFIED -> dns, truth-gate",
            )
            runOnUiThread { output.text = lines.joinToString("\n") }
        }
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }
}
