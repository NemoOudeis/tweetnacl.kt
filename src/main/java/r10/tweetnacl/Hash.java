package r10.tweetnacl;

import java.nio.charset.StandardCharsets;

/**
 * Hash algorithm, Implements SHA-512.
 */
public final class Hash {

    /**
     * @return SHA-512 hash of the message.
     */
    public static byte[] sha512(byte[] message) {
        if (!(message != null && message.length > 0))
            return null;

        byte[] out = new byte[hashLength];

        TweetNacl.crypto_hash(out, message);

        return out;
    }

    public static byte[] sha512(String message) {
        return sha512(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Length of hash in bytes.
     */
    public static final int hashLength = 64;

}
