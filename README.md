# TweetNacl in Java: port of [tweetnacl-js](https://github.com/dchest/tweetnacl-js)

Based on [tweetnacl-java](https://github.com/InstantWebP2P/tweetnacl-java).

## API/Usage

### Public key authenticated encryption

```kotlin
// generate a fresh key pair 
val keyPair = Box.keyPair()
// or from existing private key
val keyPair = Box.keyPair_fromSecretKey(sk)
val box = Box(theirPublicKey, mySecretKey, nonce)
// encryption 
val cipher: ByteArray? = box.box(message);
// decryption: 
val message: ByteArray? = box.open(cipher);
```

Nonce **MUST** be unique for every message passed between same peers

As an alternative, the nonce can be omitted from the Box() call, and passed in the box and open calls, like:

```kotlin
val nonce = ByteArray(nonceLength) 
randombytes(nonce, nonceLength)
val keyPair = Box.keyPair()

val box = Box(theirPublicKey, mySecretKey)
val cipher: ByteArray? = box.box(message, nonce)
val message: ByteArray? = box.open(cipher, nonce)
```

### Secret key authenticated encryption

* get shared key: crypto random, what you have
```kotlin
val secretBox = SecretBox(sharedKey, nonce)
val cipher: ByteArray?  = secretbox.box(message)
val message: ByteArray?  = secretbox.open(cipher)
```

Nonce **MUST** be unique for every message passed between same peers

As an alternative, the nonce can be omitted from the SecretBox() call, and passed in the box and open calls, like:

```kotlin
val nonce = ByteArray[nonceLength]
randombytes(nonce, nonceLength)
val secretBox = SecretBox(sharedKey)
val cypher: ByteArray? = secretbox.box(message, nonce)
val message: ByteArry? = secretbox.open(cipher, nonce)
```

### Signature

```kotlin
val keyPair = Signature.keyPair()
// or 
val keyPair = Signature.keyPair_fromSecretKey(sk)
val sig = Signature(theirPublicKey, mySecretKey)
val signedMessage: ByteArary? = sig.sign(message)
val message: ByteArray? = sig.open(signedMessage)
```

Nonce **MUST** be unique for every message passed between same peers

### Hash

```kotlin
val hash: ByteArray = Hash.sha512(message);
```

### About Random generation 

* the library uses `java.security.SecureRandom` for key generation
* TODO: add `/dev/urandom` as alternative source of randomness


### Testing

```shell
./gradlew test
```
