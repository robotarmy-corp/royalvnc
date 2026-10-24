// The client-to-server message queue: key, pointer and clipboard events.
//
// ── Change log (newest first, robotarmy-corp fork) ─────────────────────────
//  v1.1  2026-10-24  On Apple's "RFB 003.889" banner, swaps the middle and
//                    right buttons in pointer events. Live on mm2018, under
//                    that banner mask 0x02 opened the context menu and 0x04
//                    acted as a middle click; under 3.8 the numbering is
//                    standard. Callers keep using .right for right.
//  v1.0  (upstream)  As inherited from royalapplications/royalvnc 2026-09-21.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(CoreGraphics)
import CoreGraphics
#endif

// MARK: - Queue Management
extension VNCConnection {
	func enqueueKeyEvent(key: VNCKeyCode,
						 isDown: Bool) {
		guard settings.inputMode != .none else { return }

		let isARD = state.isAppleRemoteDesktop
		let keyCode = key.rawValue(forAppleRemoteDesktop: isARD)

		let keyEvent = VNCProtocol.KeyEvent(isDown: isDown,
											key: keyCode)

		logger.logDebug("Enqueuing Key \(keyEvent.description)")

		enqueueClientToServerMessage(keyEvent)
	}

    func enqueueMouseEvent(nonNormalizedX: UInt16,
                           nonNormalizedY: UInt16) {
        guard settings.inputMode != .none else { return }

        let normalizedPosition = normalizedMousePosition(x: nonNormalizedX,
                                                         y: nonNormalizedY)

        enqueueMouseEvent(buttons: mouseButtonState,
                          position: normalizedPosition)
    }

    func enqueueMouseEvent(buttons: VNCProtocol.MousePointerButton,
                           nonNormalizedX: UInt16,
                           nonNormalizedY: UInt16) {
        guard settings.inputMode != .none else { return }

        let normalizedPosition = normalizedMousePosition(x: nonNormalizedX,
                                                         y: nonNormalizedY)

        enqueueMouseEvent(buttons: buttons,
                          position: normalizedPosition)
    }

	func enqueueMouseEvent(buttons: VNCProtocol.MousePointerButton,
						   position: VNCProtocol.MousePosition) {
		guard settings.inputMode != .none else { return }

		var wireButtons = buttons

		// Apple's own protocol numbers buttons the macOS way: 2 is right, 3 is other.
		if state.agreedProtocolVersion?.isAppleRemoteDesktop == true {
			let middle = buttons.contains(.middle), right = buttons.contains(.right)
			wireButtons.remove([.middle, .right])
			if middle { wireButtons.insert(.right) }
			if right { wireButtons.insert(.middle) }
		}

		let pointerEvent = VNCProtocol.PointerEvent(buttons: wireButtons,
													position: position)

		enqueueClientToServerMessage(pointerEvent)
	}

	func enqueueClientCutTextMessage(_ text: String) {
		let clientCutTextMessage = VNCProtocol.ClientCutText(text: text)

		enqueueClientToServerMessage(clientCutTextMessage)
	}

	func enqueueClientToServerMessage(_ message: VNCSendableMessage) {
		clientToServerMessageQueue.enqueue(message)
	}

    func normalizedMousePosition(x: UInt16,
                                 y: UInt16) -> VNCProtocol.MousePosition {
        var normalizedX = x
        var normalizedY = y

        let framebufferWidth = framebuffer?.size.width ?? 0
        let framebufferHeight = framebuffer?.size.height ?? 0

        if normalizedY > framebufferHeight {
            normalizedY = framebufferHeight
        }

        if normalizedX > framebufferWidth {
            normalizedX = framebufferWidth
        }

        let normalizedPosition = VNCProtocol.MousePosition(x: normalizedX,
                                                           y: normalizedY)

        return normalizedPosition
    }
}
