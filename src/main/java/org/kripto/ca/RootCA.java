package org.kripto.ca;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kripto.util.CryptoUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class RootCA {
    private final KeyPair keyPair;
    private final X509Certificate certificate;
    public static final X500Name DN = new X500Name("CN=Root CA, O=EVoting, C=BA");

    public RootCA() throws Exception {
        this.keyPair = CryptoUtil.generateRSAKeyPair();
        this.certificate = selfSign();
    }

    private X509Certificate selfSign() throws Exception {
        long now = System.currentTimeMillis();
        Date from = new Date(now);
        Date to = new Date(now + 10L * 365 * 24 * 60 * 60 * 1000); // 10 godina

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(DN, BigInteger.ONE, from, to, DN, keyPair.getPublic());

        // isCA=true
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    public X509Certificate signSubCA(X500Name subjectDN, PublicKey subjectKey, int pathLen) throws Exception {
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(DN, BigInteger.valueOf(System.currentTimeMillis()), new Date(now), new Date(now + 5L * 365 * 24 * 60 * 60 * 1000), subjectDN, subjectKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    public KeyPair getKeyPair() {return keyPair;}
    public X509Certificate getCertificate() {return certificate;}
}
