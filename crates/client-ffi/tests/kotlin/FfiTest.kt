// A03: the generated Kotlin bindings, called from the JVM against the host build of
// client-ffi. A socketpair from libc stands in for the TUN fd; the server is unreachable, so
// the tunnel stays in Connecting. Run by scripts/ffi-kotlin-test.sh.

package partizan.core.test

import com.sun.jna.Library
import com.sun.jna.Native
import partizan.core.SplitConfig
import partizan.core.SplitMode
import partizan.core.StatusListener
import partizan.core.VpnConfig
import partizan.core.VpnException
import partizan.core.VpnState
import partizan.core.VpnStatus
import partizan.core.checkUri
import partizan.core.setDiagnostics
import partizan.core.stackMetrics
import partizan.core.start
import partizan.core.status
import partizan.core.stop
import java.util.concurrent.CopyOnWriteArrayList

private interface LibC : Library {
    fun socketpair(domain: Int, type: Int, protocol: Int, sv: IntArray): Int
    fun close(fd: Int): Int
}

private val libc: LibC = Native.load("c", LibC::class.java)

private const val AF_UNIX = 1
private const val SOCK_DGRAM = 2

// Well-formed, token included; nothing listens on port 1.
private const val URI =
    "partizan://00000000000000000000000000000000:" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:1?path=/sync&transport=quic"

private class Recorder : StatusListener {
    val seen = CopyOnWriteArrayList<VpnStatus>()

    override fun onStatus(status: VpnStatus) {
        seen.add(status)
    }
}

private fun check(condition: Boolean, message: () -> String) {
    if (!condition) throw AssertionError(message())
}

private fun eventually(millis: Long, condition: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + millis
    while (System.currentTimeMillis() < deadline) {
        if (condition()) return true
        Thread.sleep(50)
    }
    return false
}

private fun config(uri: String) =
    VpnConfig(uri, SplitConfig(SplitMode.INCLUDE, listOf("99.84.0.0/16", "2606:4700::/32")), 1400u)

fun main() {
    check(status().state == VpnState.IDLE) { "idle before start: ${status()}" }

    try {
        checkUri("partizan://broken")
        throw AssertionError("a broken link was accepted")
    } catch (e: VpnException.InvalidUri) {
        check(e.reason.isNotEmpty()) { "no reason given" }
    }

    setDiagnostics(true, false)
    check(stackMetrics().packetsIn == 0uL) { "metrics before start: ${stackMetrics()}" }
    setDiagnostics(false, false)

    try {
        start(-1, config(URI), Recorder())
        throw AssertionError("fd -1 was accepted")
    } catch (e: VpnException.Tun) {
        check(!e.reason.contains("AAAAAAAAAAAAAAAAAAAA")) { "token in ${e.reason}" }
    }

    val pair = IntArray(2)
    check(libc.socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0) { "socketpair failed" }
    val listener = Recorder()
    start(pair[0], config(URI), listener)
    check(eventually(5_000) { listener.seen.isNotEmpty() }) { "no status from the listener" }
    check(listener.seen.first().state == VpnState.CONNECTING) { "first: ${listener.seen}" }
    check(status().state == VpnState.CONNECTING) { "status: ${status()}" }

    try {
        start(pair[0], config(URI), Recorder())
        throw AssertionError("a second start was accepted")
    } catch (e: VpnException.AlreadyRunning) {
    }

    stop()
    check(status().state == VpnState.IDLE) { "after stop: ${status()}" }
    check(listener.seen.last().state == VpnState.IDLE) { "last: ${listener.seen}" }
    libc.close(pair[1])

    println("FFI JVM test passed: ${listener.seen.map { it.state }}")
}
