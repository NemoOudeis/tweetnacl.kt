package r10.tweetnacl

import java.util.concurrent.atomic.AtomicLong

/**
 * Secret Box algorithm, secret key
 */
class SecretBox
@JvmOverloads
constructor(
        private val key: ByteArray,
        nonce: Long = 68
) {

    private val _nonce: AtomicLong = AtomicLong(nonce)

    var nonce: Long
        get() = _nonce.get()
        set(value) = _nonce.set(value)

    fun incrNonce(): Long = _nonce.incrementAndGet()

    private fun generateNonce(): ByteArray {
        // generate nonce
        val nonce = this.nonce
        val n = ByteArray(nonceLength)
        var i = 0
        while (i < nonceLength) {
            n[i + 0] = (nonce ushr 0).toByte()
            n[i + 1] = (nonce ushr 8).toByte()
            n[i + 2] = (nonce ushr 16).toByte()
            n[i + 3] = (nonce ushr 24).toByte()
            n[i + 4] = (nonce ushr 32).toByte()
            n[i + 5] = (nonce ushr 40).toByte()
            n[i + 6] = (nonce ushr 48).toByte()
            n[i + 7] = (nonce ushr 56).toByte()
            i += 8
        }
        return n
    }

    /**
     * Encrypt and authenticates message using the key
     * and the explicitly passed nonce.
     * The nonce must be unique for each distinct message for this key.
     *
     * Returns an encrypted and authenticated message,
     * which is [SecretBox.overheadLength] longer than the original message.
     */
    ///public byte_buf_t box(byte [] message) {
    @JvmOverloads
    fun box(message: ByteArray, theNonce: ByteArray = generateNonce()): ByteArray? {
        // check message
        if (!(message.isNotEmpty() && theNonce.size == nonceLength)) return null

        // message buffer
        val m = ByteArray(message.size + zeroBytesLength)

        // cipher buffer
        val c = ByteArray(m.size)
        for (i in message.indices) m[i + zeroBytesLength] = message[i]
        if (0 != TweetNacl.crypto_secretbox(c, m, m.size, theNonce, key)) return null

        // TBD optimizing ...
        // wrap byte_buf_t on c offset@boxzerobytesLength
        ///return new byte_buf_t(c, boxzerobytesLength, c.length-boxzerobytesLength);
        val ret = ByteArray(c.size - boxZeroBytesLength)
        for (i in ret.indices) ret[i] = c[i + boxZeroBytesLength]
        return ret
    }

    /**
     * Authenticates and decrypts the given secret box
     * using the key and the explicitly passed nonce.
     *
     * @return the original message, or null if authentication fails.
     */
    @JvmOverloads
    fun open(box: ByteArray, theNonce: ByteArray = generateNonce()): ByteArray? {
        // check message
        if (!(box.size > boxZeroBytesLength && theNonce.size == nonceLength)) return null

        // cipher buffer
        val c = ByteArray(box.size + boxZeroBytesLength)

        // message buffer
        val m = ByteArray(c.size)
        for (i in box.indices) c[i + boxZeroBytesLength] = box[i]
        if (0 != TweetNacl.crypto_secretbox_open(m, c, c.size, theNonce, key)) return null

        // wrap byte_buf_t on m offset@zerobytesLength
        ///return new byte_buf_t(m, zerobytesLength, m.length-zerobytesLength);
        val ret = ByteArray(m.size - zeroBytesLength)
        for (i in ret.indices) ret[i] = m[i + zeroBytesLength]
        return ret
    }

    companion object {
        /** Length of key in bytes. */
        const val keyLength = 32

        /** Length of nonce in bytes. */
        const val nonceLength = 24

        /** Length of overhead added to secret box compared to original message. */
        const val overheadLength = 16

        /** zero bytes in case box */
        const val zeroBytesLength = 32

        /** zero bytes in case open box */
        const val boxZeroBytesLength = 16
    }
}