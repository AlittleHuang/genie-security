package io.github.genie.security.password.beans;

import io.github.genie.security.format.Decryptor;
import io.github.genie.security.format.Encryptor;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaCipher implements Decryptor, Encryptor {
    public static final String ALGORITHM = "RSA";
    private final Key key;

    /**
     * @param length 密钥长度，密钥长度必须是64的倍数，在512到65536位之间
     */
    public static KeyPair generateKeyPair(int length) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(length);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static RsaCipher ofPublic(PublicKey key) {
        return new RsaCipher(key);
    }

    public static RsaCipher ofPrivate(PrivateKey key) {
        return new RsaCipher(key);
    }

    public RsaCipher(Key key) {
        this.key = key;
    }

    public RsaCipher(SecretKeySpec key) {
        this.key = key;
    }

    @Override
    public byte[] decrypt(byte[] coded) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(coded);
    }

    @Override
    public byte[] encrypt(byte[] raw) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(raw);
    }

}
