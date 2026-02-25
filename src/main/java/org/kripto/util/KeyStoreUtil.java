package org.kripto.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

// cuva privatni kljuc + sertifikat u pkcs12 fajlu zasticenom lozinkom
public class KeyStoreUtil {
    public static void saveUserKeyStore(String alias, PrivateKey privateKey, X509Certificate userCert, X509Certificate caCert, char[] password, String filePath) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);

        X509Certificate[] chain = { userCert, caCert};
        ks.setKeyEntry(alias, privateKey, password, chain);

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            ks.store(fos, password);
        }
    }

    // ucitava keystore iz fajlsa
    public static KeyStore loadKeyStore(String filePath, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            ks.load(fis, password);
        }
        return ks;
    }

    // vraca privatni kljuc iz keystorea
    public static PrivateKey getPrivateKey(KeyStore ks, String alias, char[] password) throws Exception {
        return (PrivateKey) ks.getKey(alias, password);
    }

    // vraca sertifikat iz keystorea
    public static X509Certificate getCertificate(KeyStore ks, String alias) throws Exception {
        return (X509Certificate) ks.getCertificate(alias);
    }
}
