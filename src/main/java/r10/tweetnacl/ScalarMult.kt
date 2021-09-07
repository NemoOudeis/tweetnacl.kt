package r10.tweetnacl

/**
 * Scalar multiplication, Implements curve25519.
 */
object ScalarMult {
    /**
     * Multiplies an integer n by a group element p and
     * @return the resulting group element
     */
    fun scalseMult(n: ByteArray, p: ByteArray): ByteArray? {
        if (!(n.size == scalarLength && p.size == groupElementLength)) return null
        val q = ByteArray(scalarLength)
        TweetNacl.crypto_scalarmult(q, n, p)
        return q
    }

    /**
     * Multiplies an integer n by a standard group element and
     * @return the resulting group element.
     */
    fun scalseMult_base(n: ByteArray): ByteArray? {
        if (n.size != scalarLength) return null
        val q = ByteArray(scalarLength)
        TweetNacl.crypto_scalarmult_base(q, n)
        return q
    }

    /** Length of scalar in bytes.  */
    const val scalarLength = 32

    /** Length of group element in bytes.  */
    const val groupElementLength = 32
}