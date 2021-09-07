package r10.tweetnacl

/**
 * Signature algorithm, Implements ed25519.
 */
class Signature(private val theirPublicKey: ByteArray, private val mySecretKey: ByteArray) {
    /**
     * Signs the message using the secret key and returns a signed message.
     */
    fun sign(message: ByteArray): ByteArray {
        // signed message
        val sm = ByteArray(message.size + signatureLength)
        TweetNacl.crypto_sign(sm, -1, message, message.size, mySecretKey)
        return sm
    }

    /**
     * Verifies the signed message and returns the message without signature.
     *
     * @return null if verification failed.
     */
    fun open(signedMessage: ByteArray?): ByteArray? {
        // check sm length
        if (!(signedMessage != null && signedMessage.size > signatureLength)) return null

        // temp buffer
        val tmp = ByteArray(signedMessage.size)
        if (0 != TweetNacl.crypto_sign_open(tmp, -1, signedMessage, signedMessage.size, theirPublicKey)) return null

        // message
        val msg = ByteArray(signedMessage.size - signatureLength)
        for (i in msg.indices) msg[i] = signedMessage[i + signatureLength]
        return msg
    }

    /**
     * Signs the message using the secret key and returns a signature.
     */
    fun detached(message: ByteArray): ByteArray {
        val signedMsg = sign(message)
        val sig = ByteArray(signatureLength)
        for (i in sig.indices) sig[i] = signedMsg[i]
        return sig
    }

    /**
     * Verifies the signature for the message and
     * @return `true` if verification succeeded or `false` if it failed.
     */
    fun detached_verify(message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != signatureLength) return false
        if (theirPublicKey.size != publicKeyLength) return false
        val sm = ByteArray(signatureLength + message.size)
        val m = ByteArray(signatureLength + message.size)
        for (i in 0 until signatureLength) sm[i] = signature[i]
        for (i in message.indices) sm[i + signatureLength] = message[i]
        return TweetNacl.crypto_sign_open(m, -1, sm, sm.size, theirPublicKey) >= 0
    }

    companion object {

        /**
         * Signs the message using the secret key and returns a signed message.
         */
        @JvmStatic
        fun keyPair(): KeyPair {
            val publicKey = ByteArray(publicKeyLength)
            val secretKey = ByteArray(secretKeyLength)
            TweetNacl.crypto_sign_keypair(publicKey, secretKey, false)
            return KeyPair(publicKey, secretKey)
        }

        fun keyPair_fromSecretKey(fromSecretKey: ByteArray): KeyPair {
            val publicKey = ByteArray(publicKeyLength)
            val secretKey = ByteArray(secretKeyLength)

            // copy sk
            for (i in secretKey.indices) secretKey[i] = fromSecretKey[i]

            // copy pk from sk
            for (i in publicKey.indices) publicKey[i] = fromSecretKey[32 + i] // hard-copy
            return KeyPair(publicKey, secretKey)
        }

        @JvmStatic
        fun keyPair_fromSeed(seed: ByteArray): KeyPair {
            val publicKey = ByteArray(publicKeyLength)
            val secretKey = ByteArray(secretKeyLength)

            // copy sk
            for (i in 0 until seedLength) secretKey[i] = seed[i]

            // generate pk from sk
            TweetNacl.crypto_sign_keypair(publicKey, secretKey, true)
            return KeyPair(publicKey, secretKey)
        }

        /**
         * Length of signing public key in bytes.
         */
        const val publicKeyLength = 32

        /**
         * Length of signing secret key in bytes.
         */
        const val secretKeyLength = 64

        /**
         * Length of seed for nacl.sign.keyPair.fromSeed in bytes.
         */
        const val seedLength = 32

        /**
         * Length of signature in bytes.
         */
        const val signatureLength = 64
    }
}