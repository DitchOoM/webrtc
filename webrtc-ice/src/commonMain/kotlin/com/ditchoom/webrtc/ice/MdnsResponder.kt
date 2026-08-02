@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.AddressedDatagramSink
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress

/** The mDNS UDP port (RFC 6762 §5) — the single source of the number for both halves of the protocol. */
public const val MDNS_UDP_PORT: Int = 5353

/** RFC 1035 §3.2.3 QTYPE `*` — a querier asking for every record we hold under a name. */
private const val TYPE_ANY: Int = 255

/**
 * The **mDNS responder** (RFC 6762 §6) for the `<uuid>.local` names this session advertises — sans-io, pure,
 * `commonMain`, so it is exercised deterministically on every target under `runTest` while the multicast
 * socket that carries its bytes is a platform actual ([MulticastMdnsEndpoint]). Bytes and a source address
 * in, an exhaustive [MdnsResponse] out; the caller does the sending.
 *
 * It is **deliberately not a general-purpose responder**. It answers A / AAAA questions for the names we
 * ourselves minted and nothing else: no PTR, no SRV, no service enumeration, no proxying for other hosts.
 * Anything else on the group — and on a shared multicast group that is most of the traffic — is a typed
 * silence ([MdnsResponse.Silent]), never an answer. A responder that spoke for names it does not own would
 * be an attack surface reachable by anything on the link, in a library whose reason for existing here is
 * privacy.
 *
 * Registration is explicit ([advertise] / [withdraw]) rather than derived from the ICE agent's candidates,
 * because the name→address binding must outlive the candidate that prompted it: a peer resolves a name at
 * whatever moment its own gathering gets round to it, which is routinely after our candidate has been
 * signaled, paired and superseded.
 */
public class MdnsResponder(
    private val bufferFactory: BufferFactory = BufferFactory.Default,
) {
    // Keyed by the lowercased name: RFC 6762 §16 says a query matches a record case-insensitively, and a
    // peer that echoes our published spelling with different case must still be answered.
    private val records = LinkedHashMap<String, IpAddress>()

    /** The names this responder currently answers for, in the order they were minted. */
    public val advertisedNames: Set<MdnsHostName>
        get() = records.keys.mapTo(LinkedHashSet()) { MdnsHostName(it) }

    /** The address [name] resolves to, or null if we do not advertise it — a genuine absence. */
    public fun addressOf(name: MdnsHostName): IpAddress? = records[name.value.lowercase()]

    /**
     * Start answering A / AAAA queries for [name] with [address]. A name binds exactly one address, so
     * re-advertising a name replaces the binding rather than accumulating records — the minting side keys
     * names by address, which makes that case a re-registration of the same fact.
     */
    public fun advertise(
        name: MdnsHostName,
        address: IpAddress,
    ) {
        records[name.value.lowercase()] = address
    }

    /** Stop answering for [name]. Answering for a name whose candidate is gone would leak a stale address. */
    public fun withdraw(name: MdnsHostName) {
        records.remove(name.value.lowercase())
    }

    /**
     * Decide what to say about the query in [payload], asked by [from].
     *
     * Where the answer goes is decided by the querier's **source port**, per RFC 6762 §6.7: a query from a
     * port other than 5353 is a *one-shot legacy* query — the shape a resolve-only peer sends, and the shape
     * our own [MulticastMdnsResolver] used to send — and MUST be answered by unicast straight back to that
     * port, with the question repeated and a 10-second TTL. A query from 5353 is a full participant and gets
     * the ordinary shared response on the group. RFC 6762 §5.4's QU bit is honoured within that: a QU query
     * from 5353 still gets the multicast response, which reaches it just as surely (it is joined to the
     * group by definition) and additionally serves every other resolver on the link, so the bit changes
     * nothing we need it to change.
     *
     * [payload]'s position is consumed; ownership is not transferred.
     */
    public fun respond(
        payload: ReadBuffer,
        from: SocketAddress,
    ): MdnsResponse {
        val query =
            when (val decoded = MdnsMessage.decodeQuery(payload)) {
                MdnsMessage.QueryDecode.NotAQuery -> return MdnsResponse.Silent(MdnsSilenceReason.NotAQuery)
                MdnsMessage.QueryDecode.Malformed -> return MdnsResponse.Silent(MdnsSilenceReason.Malformed)
                is MdnsMessage.QueryDecode.Decoded -> decoded.query
            }
        if (query.questions.isEmpty()) return MdnsResponse.Silent(MdnsSilenceReason.NoQuestions)

        val answers = mutableListOf<MdnsMessage.AnswerRecord>()
        val names = mutableListOf<MdnsHostName>()
        var refusal: MdnsSilenceReason? = null
        for (question in query.questions) {
            val address = records[question.name.lowercase()]
            when {
                address == null ->
                    refusal = refusal ?: MdnsSilenceReason.NotOurs(MdnsHostName(question.name))
                question.qType != TYPE_ANY && question.qType != MdnsMessage.typeOf(address) ->
                    refusal = refusal ?: MdnsSilenceReason.UnsupportedType(question.qType)
                else -> {
                    // Answer under the spelling the querier used: it published nothing, we did, and echoing
                    // its own bytes is what a strict one-shot matcher on the far side compares against.
                    answers += MdnsMessage.AnswerRecord(question.name, address)
                    names += MdnsHostName(question.name)
                }
            }
        }
        // `refusal` is non-null whenever a question went unanswered, and at least one did if we have no
        // answers — an empty question list was rejected above. The elvis is a total function, not a guess.
        if (answers.isEmpty()) return MdnsResponse.Silent(refusal ?: MdnsSilenceReason.NoQuestions)

        val legacy = from.port != MDNS_UDP_PORT
        val shape = if (legacy) MdnsMessage.ResponseShape.Legacy(query) else MdnsMessage.ResponseShape.Shared
        val destination = if (legacy) MdnsDestination.Unicast(from) else MdnsDestination.Multicast
        return MdnsResponse.Answer(
            payload = MdnsMessage.encodeResponse(answers, shape, bufferFactory),
            destination = destination,
            names = names,
        )
    }
}

/**
 * What an [MdnsResponder] decided about one inbound datagram — a sealed outcome, not a nullable reply, so a
 * silence always carries the reason it was silent. That matters more here than it looks: "we never answered
 * the peer's query" and "we answered it with the wrong thing" are the two ways this feature fails in the
 * field, and only a named silence tells them apart in a log.
 */
public sealed interface MdnsResponse {
    /** Send [payload] to [destination]; it answers for [names], all of which are ours. */
    public data class Answer(
        public val payload: ReadBuffer,
        public val destination: MdnsDestination,
        public val names: List<MdnsHostName>,
    ) : MdnsResponse

    /** Say nothing, because of [reason]. The common case on a shared group, and never an error. */
    public data class Silent(
        public val reason: MdnsSilenceReason,
    ) : MdnsResponse
}

/** Where a response goes (RFC 6762 §6 vs §6.7) — the querier's transport decides, so the caller cannot guess. */
public sealed interface MdnsDestination {
    /** Straight back to a one-shot legacy querier's ephemeral port. */
    public data class Unicast(
        public val to: SocketAddress,
    ) : MdnsDestination

    /** The link-local mDNS group, where every resolver on the link can cache it. */
    public data object Multicast : MdnsDestination
}

/**
 * Why an [MdnsResponder] said nothing. Exhaustive and typed (directive #3) — these are the discriminants a
 * lane greps and a consumer logs, never strings.
 */
public sealed interface MdnsSilenceReason {
    /** A response, or a non-QUERY opcode. Most of what lands on a shared group; entirely routine. */
    public data object NotAQuery : MdnsSilenceReason

    /** Truncated, over-long, or corrupt. A typed reject of a datagram anything on the link could have sent. */
    public data object Malformed : MdnsSilenceReason

    /** A well-formed query that asked nothing at all. */
    public data object NoQuestions : MdnsSilenceReason

    /**
     * The name asked about is not one we advertise. The privacy-critical refusal: a responder that answered
     * here would be speaking for a host it is not, on a link it merely shares.
     */
    public data class NotOurs(
        public val name: MdnsHostName,
    ) : MdnsSilenceReason

    /** Ours, but asked for a record type we do not hold for it (an A where we have only a AAAA, PTR, SRV…). */
    public data class UnsupportedType(
        public val qType: Int,
    ) : MdnsSilenceReason
}

/**
 * Answer one received [datagram] on [channel] — the composable unit of the responder's I/O, so a driver
 * that owns a *shared* socket (queries in, its own resolutions' responses in) can dispatch to it without
 * giving up its own receive loop. [group] is where a [MdnsDestination.Multicast] response is sent.
 *
 * Returns what was decided, including the silences, so the caller can observe a refusal rather than infer
 * one from the absence of a packet.
 */
public suspend fun MdnsResponder.serveOne(
    channel: AddressedDatagramSink,
    datagram: Datagram,
    group: SocketAddress,
): MdnsResponse {
    val response = respond(datagram.payload, datagram.peer)
    when (response) {
        is MdnsResponse.Silent -> Unit
        is MdnsResponse.Answer ->
            channel.send(
                response.payload,
                to =
                    when (val destination = response.destination) {
                        is MdnsDestination.Unicast -> destination.to
                        MdnsDestination.Multicast -> group
                    },
            )
    }
    return response
}

/**
 * Serve mDNS queries arriving on [channel] until it closes — the whole responder driver, in `commonMain`
 * over the buffer-flow seam, so the identical loop runs over a real multicast socket in production and over
 * the in-memory vnet under `runTest` on every target. [group] is the multicast destination for a shared
 * response; [onResponse] observes every decision, answers and silences alike.
 */
public suspend fun MdnsResponder.serve(
    channel: AddressedDatagramChannel,
    group: SocketAddress,
    onResponse: (MdnsResponse) -> Unit = {},
) {
    while (true) {
        val datagram =
            when (val result = channel.receiveOrClosed()) {
                is DatagramReadResult.Received -> result.datagram
                is DatagramReadResult.Closed -> return
            }
        onResponse(serveOne(channel, datagram, group))
    }
}
