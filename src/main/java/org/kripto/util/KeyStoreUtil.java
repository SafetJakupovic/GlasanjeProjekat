package org.kripto.util;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.jcajce.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;

// cuva privatni kljuc + sertifikat u pkcs12 fajlu zasticenom lozinkom
// pokusao prvo sa java keystore, ali izgleda da to koristi prestare algoritme koje ne mogu testirati (barem ne lako) sa openssl pa sam prebacio na bouncycastle
public class KeyStoreUtil {
    static {
        if(Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    public static void saveUserKeyStore(String alias, PrivateKey privateKey, X509Certificate userCert, X509Certificate caCert, char[] password, String filePath) throws Exception {
        // definisanje algoritma za enkripciju privatnog kljuca, valjda nije previse iteracija
        OutputEncryptor keyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").setIterationCount(204800).build(password);

        // pakovajne privatnog kljuca u safebag
        JcaPKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privateKey, keyEncryptor);
        keyBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new org.bouncycastle.asn1.DERBMPString(alias));

        byte[] localKeyId = computeLocalKeyId(userCert.getPublicKey());
        keyBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, new org.bouncycastle.asn1.DEROctetString(localKeyId));

        //pakovanje korisnickog sertifikata u safebag
        X509CertificateHolder userCertHolder = new JcaX509CertificateHolder(userCert);
        PKCS12SafeBagBuilder certBagBuilder = new PKCS12SafeBagBuilder(userCertHolder);
        certBagBuilder.addBagAttribute(
                PKCS12SafeBag.friendlyNameAttribute,
                new DERBMPString(alias));
        certBagBuilder.addBagAttribute(
                PKCS12SafeBag.localKeyIdAttribute,
                new DEROctetString(localKeyId));

        // pakovanje ca sertifikata u safebag
        PKCS12SafeBagBuilder caCertBagBuilder = new PKCS12SafeBagBuilder(new JcaX509CertificateHolder(caCert));
        caCertBagBuilder.addBagAttribute(
                PKCS12SafeBag.friendlyNameAttribute,
                new org.bouncycastle.asn1.DERBMPString("ca-cert"));

        // sastavljanje pkcs12 strukture
        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();

        // Sertifikati — enkriptujemo isti algoritam
        OutputEncryptor certEncryptor = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").setIterationCount(204800).build(password);

        pfxBuilder.addEncryptedData(certEncryptor, new PKCS12SafeBag[]{
                certBagBuilder.build(),
                caCertBagBuilder.build()
        });

        // Privatni ključ — ide u poseban SafeContents
        pfxBuilder.addData(keyBagBuilder.build());

        // mac zastita integriteta
        PKCS12PfxPdu pfx = pfxBuilder.build(
                new JcePKCS12MacCalculatorBuilder()
                        .setProvider("BC"),
                password);

        // ── Korak 7: Pisanje na disk ─────────────────────────────────────────
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            // getEncoded() serializuje PKCS#12 u DER binarni format
            fos.write(pfx.getEncoded());
        }
    }

    // izracunava localkeyid iz javnog kljuca
    private static byte[] computeLocalKeyId(PublicKey publicKey) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1", "BC");
        return sha1.digest(publicKey.getEncoded());
    }

    public static KeyStore loadKeyStore(String filePath, char[] password) throws Exception {
        // "PKCS12" bez provajdera — Java bira dostupan provajder (SunJSSE ili BC)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            ks.load(fis, password);
        }
        return ks;
    }

    public static PrivateKey getPrivateKey(KeyStore ks, String alias,
                                           char[] password) throws Exception {
        return (PrivateKey) ks.getKey(alias, password);
    }

    public static X509Certificate getCertificate(KeyStore ks, String alias) throws Exception {
        return (X509Certificate) ks.getCertificate(alias);
    }
}
