package org.kripto.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class CryptoUtil {
    static {
        if(Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(2048, new SecureRandom());
        return gen.generateKeyPair();
    }

    // hashira lozinku sa SHA-256 + salt
    public static byte[] hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
        md.update(salt);
        return md.digest(password.getBytes("UTF-8"));
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}
