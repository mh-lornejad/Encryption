import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

fun decryptAES(key: ByteArray, ciphertext: ByteArray): String {
    val iv = ciphertext.sliceArray(0 until 16) // Extract IV from ciphertext
    val encrypted = ciphertext.sliceArray(16 until ciphertext.size)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val secretKey = SecretKeySpec(key, "AES")
    val ivParams = IvParameterSpec(iv)

    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams)
    val decryptedBytes = cipher.doFinal(encrypted)

    return String(decryptedBytes)
}

fun main() {
    val key = "32-byte-long-encryption-key".toByteArray() // Replace with your AES key
    val encryptedBase64 = "<Base64 Encoded Ciphertext from Go>".toByteArray()
    val encryptedBytes = Base64.getDecoder().decode(encryptedBase64)

    val decryptedMessage = decryptAES(key, encryptedBytes)
    println("Decrypted: $decryptedMessage")
}
