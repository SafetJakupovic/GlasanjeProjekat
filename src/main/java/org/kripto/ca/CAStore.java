package org.kripto.ca;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class CAStore {
    // Interna lozinka za CA keystore fajlove
    // U realnom sistemu ovo bi bio konfiguracijski parametar ili HSM
    private static final char[] CA_PASSWORD = "ca-internal-secret".toCharArray();

    private static final String ROOT_CA_PATH  = "ca/root_ca.p12";
    private static final String ORG_CA_PATH   = "ca/org_ca.p12";
    private static final String VOTER_CA_PATH = "ca/voter_ca.p12";

    static {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Inicijalizuje CA hijerarhiju:
     *   - Ako fajlovi postoje na disku → učitava postojeće CA
     *   - Ako ne postoje → kreira novu hijerarhiju i čuva je
     */
    public static RootCA loadOrCreateRootCA() throws Exception {
        new File("ca").mkdirs();
        if (new File(ROOT_CA_PATH).exists()) {
            System.out.println("  Učitavam Root CA sa diska...");
            return RootCA.loadFromDisk(ROOT_CA_PATH, CA_PASSWORD);
        } else {
            System.out.println("  Kreiram novi Root CA...");
            RootCA ca = new RootCA();
            ca.saveToDisk(ROOT_CA_PATH, CA_PASSWORD);
            return ca;
        }
    }

    public static OrgCA loadOrCreateOrgCA(RootCA rootCA) throws Exception {
        if (new File(ORG_CA_PATH).exists()) {
            System.out.println("  Učitavam Org CA sa diska...");
            return OrgCA.loadFromDisk(ORG_CA_PATH, CA_PASSWORD, rootCA);
        } else {
            System.out.println("  Kreiram novi Org CA...");
            OrgCA ca = new OrgCA(rootCA);
            ca.saveToDisk(ORG_CA_PATH, CA_PASSWORD);
            return ca;
        }
    }

    public static VoterCA loadOrCreateVoterCA(RootCA rootCA) throws Exception {
        if (new File(VOTER_CA_PATH).exists()) {
            System.out.println("  Učitavam Voter CA sa diska...");
            return VoterCA.loadFromDisk(VOTER_CA_PATH, CA_PASSWORD, rootCA);
        } else {
            System.out.println("  Kreiram novi Voter CA...");
            VoterCA ca = new VoterCA(rootCA);
            ca.saveToDisk(VOTER_CA_PATH, CA_PASSWORD);
            return ca;
        }
    }

    public static void saveOrgCRL(List<BigInteger> revoked) throws Exception {
        new File("ca").mkdirs();
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream("ca/org_crl.ser"))) {
            oos.writeObject(revoked);
        }
    }

    public static List<BigInteger> loadOrgCRL() throws Exception {
        File f = new File("ca/org_crl.ser");
        if (!f.exists()) return new ArrayList<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            return (List<BigInteger>) ois.readObject();
        }
    }

    public static void saveVoterCRL(List<BigInteger> revoked) throws Exception {
        new File("ca").mkdirs();
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream("ca/voter_crl.ser"))) {
            oos.writeObject(revoked);
        }
    }

    public static List<BigInteger> loadVoterCRL() throws Exception {
        File f = new File("ca/voter_crl.ser");
        if (!f.exists()) return new ArrayList<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            return (List<BigInteger>) ois.readObject();
        }
    }
}
