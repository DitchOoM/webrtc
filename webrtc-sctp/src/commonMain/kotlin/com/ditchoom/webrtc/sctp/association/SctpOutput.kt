package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId

/**
 * A side effect the driver must perform for the [SctpAssociation]. The core returns these from
 * `handle`; it never touches the transport itself. Exhaustive and sealed so a driver `when`s over it
 * with no `else` (DESIGN_PRINCIPLES §3).
 */
public sealed interface SctpOutput {
    /**
     * Send [packet] over the transport below (DTLS → the selected ICE pair). It is positioned for
     * reading with the CRC32c already placed — the driver just hands it to `DatagramChannel.send`.
     *
     * **Read-only, and not the driver's to free.** [packet] is a private read view: for a DATA chunk it
     * spans the encoded packet the retransmission queue still owns (so a retransmit can re-emit the same
     * bytes), and the association frees it when the chunk is acked or abandoned. Reading it — including
     * moving this view's own position/limit or slicing it further — is fine and is what the driver does;
     * writing into it or releasing it would corrupt or invalidate a future retransmission.
     */
    public data class Transmit(
        public val packet: PlatformBuffer,
    ) : SctpOutput

    /** The association lifecycle state changed (RFC 4960 §4) — surfaced to the DataChannel/PeerConnection layer. */
    public data class StateChanged(
        public val state: SctpAssociationState,
    ) : SctpOutput

    /**
     * A complete user message was reassembled and is ready for delivery to the upper layer, in the
     * correct order for its stream. [payload] is a fresh caller-owned buffer (the reassembly copy); the
     * driver owns it. [unordered] and [payloadProtocolId] let the DataChannel layer route DCEP vs. app
     * data (RFC 8831 §6.6).
     */
    public data class MessageReceived(
        public val streamId: StreamId,
        public val payloadProtocolId: PayloadProtocolId,
        public val unordered: Boolean,
        public val payload: ReadBuffer,
    ) : SctpOutput

    /**
     * The association reached a terminal failure (RFC 4960 §8.1 error threshold, a received ABORT, or a
     * malformed handshake). Carries the typed [reason] (never a string — directive #3). The driver
     * tears down the DataChannels.
     */
    public data class Aborted(
        public val reason: SctpFailureReason,
    ) : SctpOutput
}
