package r10.tweetnacl

import java.util.concurrent.atomic.AtomicLong

/**
 * Box algorithm, Public-key authenticated encryption
 */
class Box
@JvmOverloads
constructor(
        private val theirPublicKey: ByteArray,
        private val mySecretKey: ByteArray,
        nonce: Long = 68
) {
    private lateinit var sharedKey: ByteArray

    init {
        // generate pre-computed shared key
        before()
    }

    private val _nonce: AtomicLong = AtomicLong(nonce)
    var nonce: Long
        get() = _nonce.get()
        set(value) = _nonce.set(value)

    fun incrNonce(): Long = _nonce.incrementAndGet()


    private fun generateNonce(): ByteArray {
        // generate nonce
        val nonce = _nonce.get()
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
     * Encrypt and authenticates message using peer's public key,
     * our secret key, and the given nonce, which must be unique
     * for each distinct message for a key pair.
     *
     * @return  an encrypted and authenticated message, which is [Box.overheadLength] longer than the original message.
     *          (or null if something goes wrong)
     **/
    ///public byte_buf_t box(byte [] message) {
    @JvmOverloads
    fun box(message: ByteArray, nonce: ByteArray = generateNonce()): ByteArray? {

        // check message
        if (!(message.isNotEmpty() && nonce.size == nonceLength)) return null

        // message buffer
        val m = ByteArray(message.size + zerobytesLength)

        // cipher buffer
        val c = ByteArray(m.size)
        for (i in message.indices) m[i + zerobytesLength] = message[i]
        if (0 != TweetNacl.crypto_box(c, m, m.size, nonce, theirPublicKey, mySecretKey)) return null

        // wrap byte_buf_t on c offset@boxzerobytesLength
        ///return new byte_buf_t(c, boxzerobytesLength, c.length-boxzerobytesLength);
        val ret = ByteArray(c.size - boxzerobytesLength)
        for (i in ret.indices) ret[i] = c[i + boxzerobytesLength]
        return ret
    }

    /*
     * @description
     *   Authenticates and decrypts the given box with peer's public key,
     *   our secret key, and the given nonce.
     *
     *   Returns the original message, or null if authentication fails.
     * */
    @JvmOverloads
    fun open(box: ByteArray, nonce: ByteArray = generateNonce()): ByteArray? {
        // check message
        if (!(box.size > boxzerobytesLength && nonce.size == nonceLength)) return null

        // cipher buffer
        val c = ByteArray(box.size + boxzerobytesLength)

        // message buffer
        val m = ByteArray(c.size)
        for (i in box.indices) c[i + boxzerobytesLength] = box[i]
        if (0 != TweetNacl.crypto_box_open(m, c, c.size, nonce, theirPublicKey, mySecretKey)) return null

        // wrap byte_buf_t on m offset@zerobytesLength
        ///return new byte_buf_t(m, zerobytesLength, m.length-zerobytesLength);
        val ret = ByteArray(m.size - zerobytesLength)
        for (i in ret.indices) ret[i] = m[i + zerobytesLength]
        return ret
    }

    /*
     * @description
     *   Returns a precomputed shared key
     *   which can be used in nacl.box.after and nacl.box.open.after.
     * */
    @Suppress("MemberVisibilityCanBePrivate")
    fun before(): ByteArray? {
        if (!::sharedKey.isInitialized) {
            sharedKey = ByteArray(sharedKeyLength)
            TweetNacl.crypto_box_beforenm(sharedKey, theirPublicKey, mySecretKey)
        }
        return sharedKey
    }

    /*
     * @description
     *   Same as nacl.box, but uses a shared key precomputed with nacl.box.before.
     * */
    @JvmOverloads
    fun after(message: ByteArray, nonce: ByteArray = generateNonce()): ByteArray? {
        // check message
        if (!(message.isNotEmpty() && nonce.size == nonceLength)) return null

        // message buffer
        val m = ByteArray(message.size + zerobytesLength)

        // cipher buffer
        val c = ByteArray(m.size)
        for (i in message.indices) m[i + zerobytesLength] = message[i]
        if (0 != TweetNacl.crypto_box_afternm(c, m, m.size, nonce, sharedKey)) return null

        // wrap byte_buf_t on c offset@boxzerobytesLength
        ///return new byte_buf_t(c, boxzerobytesLength, c.length-boxzerobytesLength);
        val ret = ByteArray(c.size - boxzerobytesLength)
        for (i in ret.indices) ret[i] = c[i + boxzerobytesLength]
        return ret
    }

    /*
     * @description
     *   Same as nacl.box.open,
     *   but uses a shared key pre-computed with nacl.box.before.
     * */
    @JvmOverloads
    fun open_after(box: ByteArray, theNonce: ByteArray = generateNonce()): ByteArray? {
        // check message
        if (!(box.size > boxzerobytesLength && theNonce.size == nonceLength)) return null

        // cipher buffer
        val c = ByteArray(box.size + boxzerobytesLength)

        // message buffer
        val m = ByteArray(c.size)
        for (i in box.indices) c[i + boxzerobytesLength] = box[i]
        if (TweetNacl.crypto_box_open_afternm(m, c, c.size, theNonce, sharedKey) != 0) return null

        // wrap byte_buf_t on m offset@zerobytesLength
        ///return new byte_buf_t(m, zerobytesLength, m.length-zerobytesLength);
        val ret = ByteArray(m.size - zerobytesLength)
        for (i in ret.indices) ret[i] = m[i + zerobytesLength]
        return ret
    }

    companion object {

        /** Length of public key in bytes. */
        const val publicKeyLength = 32

        /** Length of secret key in bytes. */
        const val secretKeyLength = 32

        /** Length of precomputed shared key in bytes. */
        const val sharedKeyLength = 32

        /** Length of nonce in bytes. */
        const val nonceLength = 24

        /** zero bytes in case box */
        const val zerobytesLength = 32

        /** zero bytes in case open box */
        const val boxzerobytesLength = 16

        /** Length of overhead added to box compared to original message. */
        const val overheadLength = 16

        /**
         * Generates a new random key pair for box.
         * @return [KeyPair] with publicKey and secretKey.
         */
        @JvmStatic
        fun keyPair(): KeyPair {
            val secretKey = ByteArray(secretKeyLength)
            val publicKey = ByteArray(publicKeyLength)

            TweetNacl.randombytes(secretKey, secretKeyLength)
            TweetNacl.crypto_scalarmult_base(publicKey, secretKey)

            return KeyPair(publicKey, secretKey)
        }

        @JvmStatic
        fun keyPair_fromSecretKey(fromSecretKey: ByteArray): KeyPair {
            val secretKey = ByteArray(secretKeyLength)
            val publicKey = ByteArray(publicKeyLength)

            // copy sk
            for (i in secretKey.indices) secretKey[i] = fromSecretKey[i]
            TweetNacl.crypto_scalarmult_base(publicKey, secretKey)
            return KeyPair(publicKey, secretKey)
        }
    }
}