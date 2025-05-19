package org.bread_experts_group

import org.bread_experts_group.coder.Base32
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPasswordField
import javax.swing.SwingUtilities
import kotlin.experimental.and
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.system.exitProcess

@OptIn(ExperimentalEncodingApi::class)
fun main() {
	var totpSecret: CharArray? = null
	run {
		val jpf = JPasswordField()
		val jop = JOptionPane(
			jpf, JOptionPane.QUESTION_MESSAGE,
			JOptionPane.OK_CANCEL_OPTION
		)
		val dialog = jop.createDialog("TOTP Secret Key")
		dialog.addComponentListener(object : ComponentAdapter() {
			override fun componentShown(e: ComponentEvent) {
				SwingUtilities.invokeLater { jpf.requestFocusInWindow() }
			}
		})
		dialog.isVisible = true
		val result = jop.getValue() as Int
		dialog.dispose()
		if (result == JOptionPane.OK_OPTION) totpSecret = jpf.getPassword()
	}
	if (totpSecret == null) exitProcess(0)
	try {
		val mac = Mac.getInstance("HmacSHA1")
		mac.init(SecretKeySpec(Base32.decode(totpSecret.concatToString()), "HmacSHA1"))
		val buffer = ByteBuffer.allocate(8)
		buffer.order(ByteOrder.BIG_ENDIAN)
		buffer.putLong((System.currentTimeMillis() / 1000) / 30)
		val maced = mac.doFinal(buffer.array())
		val offset = maced.last() and 0xF
		val extracted = maced
			.sliceArray(offset..offset+3)
			.joinToString("") { it.toUByte().toString(16) }
			.toLong(16) and 0x7FFFFFFF
		val secondsRemaining = 30 - ((System.currentTimeMillis() / 1000) % 30).toInt()
		val jpf = JLabel("OTP [${secondsRemaining}s]: ${extracted % 1000000}")
		val jop = JOptionPane(
			jpf, JOptionPane.INFORMATION_MESSAGE,
			JOptionPane.DEFAULT_OPTION
		)
		val dialog = jop.createDialog("Extraction Complete")
		dialog.isVisible = true
		dialog.dispose()
	} catch (e: Exception) {
		val jpf = JLabel("Failure to extract OTP: [${e.javaClass.canonicalName}]: ${e.localizedMessage}")
		val jop = JOptionPane(
			jpf, JOptionPane.ERROR_MESSAGE,
			JOptionPane.DEFAULT_OPTION
		)
		val dialog = jop.createDialog("Extraction Failure")
		dialog.isVisible = true
		dialog.dispose()
	}
}