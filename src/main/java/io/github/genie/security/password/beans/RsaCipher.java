package io.github.genie.security.password.beans;

import io.github.genie.security.exception.UncheckedSecurityException;
import io.github.genie.security.format.Decryptor;
import io.github.genie.security.format.Encryptor;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaCipher implements Decryptor, Encryptor {
    public static final String ALGORITHM = "RSA";
    private final Key key;

    /**
     * generate KeyPair
     *
     * @param length Key length, which must be a multiple of 64, between 512 and 65536
     */
    public static KeyPair generateKeyPair(int length) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(length);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UncheckedSecurityException(e);
        }
    }

    public static RsaCipher ofPublic(PublicKey key) {
        return new RsaCipher(key);
    }

    public static RsaCipher ofPrivate(PrivateKey key) {
        return new RsaCipher(key);
    }

    @NotNull
    public static RsaCipher ofPublic(byte[] key) throws GeneralSecurityException {
        X509EncodedKeySpec pkcs8KeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey privateKey = keyFactory.generatePublic(pkcs8KeySpec);
        return RsaCipher.ofPublic(privateKey);
    }

    @NotNull
    public static RsaCipher ofPrivate(byte[] key) throws GeneralSecurityException {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        return RsaCipher.ofPrivate(privateKey);
    }

    public RsaCipher(Key key) {
        this.key = key;
    }

    @Override
    public byte @NotNull [] decrypt(byte @NotNull [] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    @Override
    public byte @NotNull [] encrypt(byte @NotNull [] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new UncheckedSecurityException(e);
        }
    }

}
