package io.github.genie.security.password.beans;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;


class RsaCipherTest {

    @Test
    void decrypt() throws GeneralSecurityException {
        KeyPair keyPair = RsaCipher.generateKeyPair(1024);
        RsaCipher pub = RsaCipher.ofPublic(keyPair.getPublic());
        RsaCipher pri = RsaCipher.ofPrivate(keyPair.getPrivate());
        testDecrypt(pub, pri);

        pub = RsaCipher.ofPublic(keyPair.getPublic().getEncoded());
        pri = RsaCipher.ofPrivate(keyPair.getPrivate().getEncoded());
        testDecrypt(pub, pri);

    }

    private static void testDecrypt(RsaCipher pub, RsaCipher pri) throws GeneralSecurityException {
        byte[] bytes = new byte[117];
        byte[] pubEnc = pub.encrypt(bytes);
        Assertions.assertFalse(Arrays.equals(bytes, pubEnc));
        Assertions.assertFalse(Arrays.equals(pub.encrypt(bytes), pubEnc));
        byte[] decrypt = pri.decrypt(pubEnc);
        Assertions.assertArrayEquals(bytes, decrypt);
    }

    @Test
    void gen() {
        KeyPair keyPair = RsaCipher.generateKeyPair(1024);
        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println();
        System.out.println(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

}