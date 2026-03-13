package org.kripto.voting;

import org.kripto.model.Poll;
import org.kripto.model.Vote;
import org.kripto.registration.RegistrationService;
import org.kripto.util.KeyStoreUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

// upravljanje glasanjima (kreiranje, glasanje, brojanje)
public class PollService {
    private final RegistrationService regService;
    // pollid -> poll
    private final Map<String, Poll> polls = new LinkedHashMap<>();
    // korisnicko ime glasaca -> set pollidova gdje je glasao
    // vise radi brze provjere
    private final Map<String, Set<String>> voterHistory = new HashMap<>();

    public PollService(RegistrationService regService) {
        this.regService = regService;
    }

    // kreiranje glasanja
    public Poll createPoll(String organizerUsername, String title, String description, Instant startTime, Instant endTime, List<String> options, String organizerKeystorePath, char[] password) throws  Exception {
        // provjera da li je organizator registrovan
        RegistrationService.UserRecord rec = regService.getUsers().get(organizerUsername);
        if(rec == null || !rec.role.equals("ORGANIZER"))
            throw new IllegalArgumentException("Korisnik nije organizator: " + organizerUsername);

        if(endTime.isBefore(startTime))
            throw new IllegalArgumentException("Kraj mora biti poslije pocetka");

        String pollId = UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        // hmac zastita podataka
        KeyStore ks = KeyStoreUtil.loadKeyStore(organizerKeystorePath, password);
        PrivateKey orgPrivKey = KeyStoreUtil.getPrivateKey(ks, organizerUsername, password);
        byte[] hmacKey = deriveHmacKey(orgPrivKey);

        // sadrzaj koji stitimo hmacom
        byte[] metadata = buildMetadataBytes(pollId, title, options, startTime, endTime);
        byte[] hmac = computeHmac(metadata, hmacKey);

        Poll poll = new Poll(pollId, organizerUsername, title, description, startTime, endTime, options, hmac);
        polls.put(pollId, poll);

        System.out.println("Glasanje kreirano: " + pollId);
        return poll;
    }

    // vraca sva glasanja datog organizatora
    public List<Poll> getPollsByOrganizer(String organizerUsername) {
        return polls.values().stream()
                .filter(p -> p.organizerUsername.equals(organizerUsername))
                .sorted(Comparator.comparing(p -> p.startTime))
                .toList();
    }

    // vraca listu aktivnih glasanja u kojima glasac nije jos glasao
    public List<Poll> getActivePollsForVoter(String voterUsername) {
        Set<String> voted = voterHistory.getOrDefault(voterUsername, Set.of());
        return polls.values().stream()
                .filter(p -> p.getStatus() == Poll.Status.ACTIVE)
                .filter(p -> !voted.contains(p.id))
                .toList();
    }

    // glasac glasa
    public String castVote(String pollId, String chosenOption, String voterUsername, String voterKeystorePath, char[] voterPassword) throws Exception {
        Poll poll = getPollOrThrow(pollId);

        if(!poll.options.contains(chosenOption))
            throw new IllegalArgumentException("Opcija ne postoji: " + chosenOption + ". Dostupne: " + poll.options);

        KeyStore ks = KeyStoreUtil.loadKeyStore(voterKeystorePath, voterPassword);
        PrivateKey voterPrivKey = KeyStoreUtil.getPrivateKey(ks, voterUsername, voterPassword);
        X509Certificate voterCert = KeyStoreUtil.getCertificate(ks, voterUsername);

        // pronalazak javnog kljuca organizatora
        RegistrationService.UserRecord orgRecord = regService.getUsers().get(poll.organizerUsername);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        if(orgRecord == null)
            throw new IllegalStateException("Organizator nije pronadjen");

        //KeyStore orgKs = KeyStoreUtil.loadKeyStore(orgRecord.keystorePath, null); //cita se samo cert, ne treba lozinka
        X509Certificate orgCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(orgRecord.encodedCertificate));
        PublicKey orgPublicKey = orgCert.getPublicKey();

        /*try {
            orgKs = KeyStoreUtil.loadKeyStore(orgRecord.keystorePath, new char[0]); //dummy
            orgCert = KeyStoreUtil.getCertificate(orgKs, poll.organizerUsername);
        } catch (Exception e) {
            throw new IllegalStateException("Ne moze se ucitati sertifikat organizatora. " + "Provjeri da li su keystorePath i lozinka ispravni. " + "Greška: " + e.getMessage());
        }*/

        VotingCrypto.EncryptedVoteData enc = VotingCrypto.encrypt(chosenOption, orgPublicKey);
        byte[] signature = VotingCrypto.sign(enc.encryptedChoice, enc.encryptedAesKey, enc.iv, voterPrivKey);
        Vote vote = new Vote(pollId, enc.encryptedChoice, enc.encryptedAesKey, enc.iv, signature, voterCert.getSerialNumber());

        poll.addVote(vote);

        voterHistory.computeIfAbsent(voterUsername, k -> new HashSet<>()).add(pollId);

        System.out.println("Glas uspjesno upisan. VoteID: " + vote.voteId);
        return vote.voteId;
    }

    public String verifyVote(String pollId, String voteId, X509Certificate voterCert) throws Exception {
        Poll poll = getPollOrThrow(pollId);

        Optional<Vote> maybeVote = poll.findVoteById(voteId);
        if (maybeVote.isEmpty())
            return "Glas sa ID-om " + voteId + " nije pronadjen u sistemu";

        Vote vote = maybeVote.get();

        boolean sigValid = VotingCrypto.verify(vote.encryptedChoice, vote.encryptedAesKey, vote.iv, vote.signature, voterCert);

        if (!sigValid)
            return "Potpis nije validan";

        return String.format(
                "Glas potvrđen.\n" +
                        "  VoteID:    %s\n" +
                        "  Glasanje:  %s\n" +
                        "  Upisano:   %s\n" +
                        "  Potpis:    VALIDAN\n",
                vote.voteId, poll.title, vote.timestamp);
    }

    public Map<String, Integer> countVotes(String pollId, String organizerUsername, String organizerKeystorePath, char[] password) throws Exception {
        Poll poll = getPollOrThrow(pollId);

        if(!poll.organizerUsername.equals(organizerUsername))
            throw new SecurityException("Samo organizator koji je kreirao glasanje moze brojati");

        if (poll.getStatus() == Poll.Status.ACTIVE)
            throw new IllegalStateException("Glasanje je jos aktivno");

        if (poll.getStatus() == Poll.Status.COUNTED)
            return poll.getResults();

        KeyStore ks = KeyStoreUtil.loadKeyStore(organizerKeystorePath, password);
        PrivateKey orgPrivKey = KeyStoreUtil.getPrivateKey(ks, organizerUsername, password);
        X509Certificate orgCert = KeyStoreUtil.getCertificate(ks, organizerUsername);

        byte[] hmacKey = deriveHmacKey(orgPrivKey);
        byte[] metadata = buildMetadataBytes(pollId, poll.title, poll.options, poll.startTime, poll.endTime);
        byte[] expectedHmac = computeHmac(metadata, hmacKey);
        if (!Arrays.equals(expectedHmac, poll.metadataHmac))
            throw new SecurityException("HMAC verifikacija metapodataka nije prosla");

        Map<String, Integer> results = new LinkedHashMap<>();
        for(String opt : poll.options)
            results.put(opt, 0);

        int invalidVotes = 0;

        for(Vote vote : poll.getVotes()) {
            try {
                // pronalazak sertifikata glasaca po serijalu
                X509Certificate voterCert = findCertBySerial(vote.voterCertSerial);
                if(voterCert == null) {
                    System.out.println("Sertifikat za serial: " + vote.voterCertSerial + " nije pronadjen. Glas preskocen");
                    invalidVotes++;
                    continue;
                }

                // vertifikovanja potpisa glasaca
                boolean sigOk = VotingCrypto.verify(vote.encryptedChoice, vote.encryptedAesKey, vote.iv, vote.signature, voterCert);
                if(!sigOk) {
                    System.out.println("Nevazeci potpis za voteId: " + vote.voteId + ". Glas odbacen");
                    invalidVotes++;
                    continue;
                }

                // dekriptovanje glasa
                String choice = VotingCrypto.decrypt(vote.encryptedChoice, vote.encryptedAesKey, vote.iv, orgPrivKey);

                // brojanje
                results.merge(choice, 1, Integer::sum);
            } catch (Exception e) {
                System.out.println("Greska pri obradi glasa " + vote.voteId + ": " + e.getMessage());
                invalidVotes++;
            }
        }

        poll.setResults(results);

        byte[] report = generateSignedReport(poll, results, invalidVotes, orgPrivKey);
        poll.setSignedReport(report);

        System.out.println("Brojanje zavrseno");
        if(invalidVotes > 0)
            System.out.println("Nevazecih glasova: " + invalidVotes);

        return results;
    }

    public void printResults(String pollId) {
        Poll poll = polls.get(pollId);
        if (poll == null || poll.getResults() == null) {
            System.out.println("Rezultati nisu dostupni");
            return;
        }

        System.out.println("\n====================================");
        System.out.println("  REZULTATI: " + poll.title);
        System.out.println("====================================");
        int total = poll.getResults().values().stream().mapToInt(i -> i).sum();
        poll.getResults().forEach((opt, count) -> {
            int pct = total > 0 ? (count * 100 / total) : 0;
            System.out.printf("  %-20s %3d glasova (%d%%)%n", opt, count, pct);
        });
        System.out.println("  --------------------------------");
        System.out.println("  Ukupno glasova: " + total);
        System.out.println("====================================");
    }

    public void printSignedReport(String pollId, X509Certificate orgCert) throws Exception {
        Poll poll = getPollOrThrow(pollId);
        byte[] combined = poll.getSignedReport();
        if (combined == null) {
            System.out.println("Izvjestaj nije generisan");
            return;
        }

        int reportLen = ((combined[0] & 0xFF) << 24) | ((combined[1] & 0xFF) << 16)
                | ((combined[2] & 0xFF) << 8)  | (combined[3] & 0xFF);
        byte[] reportBytes = Arrays.copyOfRange(combined, 4, 4 + reportLen);
        byte[] sig = Arrays.copyOfRange(combined, 4 + reportLen, combined.length);

        System.out.println(new String(reportBytes, "UTF-8"));

        Signature verifier = Signature.getInstance("SHA256withRSA", "BC");
        verifier.initVerify(orgCert.getPublicKey());
        verifier.update(reportBytes);
        boolean valid = verifier.verify(sig);
        System.out.println("Potpis izvjestaja: " + (valid ? "VALIDAN" : "NEVAŽEĆI"));
    }

    public Map<String, Poll> getAllPolls() {
        return Collections.unmodifiableMap(polls);
    }

    public void loadPolls(Map<String, Poll> loaded) {
        polls.putAll(loaded);
    }

    public void loadVoterHistory(Map<String, Set<String>> history) {
        voterHistory.putAll(history);
    }

    public Map<String, Set<String>> getVoterHistory() {
        return Collections.unmodifiableMap(voterHistory);
    }

    private byte[] generateSignedReport(Poll poll, Map<String, Integer> results, int invalidVotes, PrivateKey orgPrivKey) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("IZVJEŠTAJ O GLASANJU\n");
        sb.append("ID: ").append(poll.id).append("\n");
        sb.append("Naslov: ").append(poll.title).append("\n");
        sb.append("Period: ").append(poll.startTime).append(" - ").append(poll.endTime).append("\n");
        sb.append("Generisan: ").append(Instant.now()).append("\n");
        sb.append("Organizator: ").append(poll.organizerUsername).append("\n\n");
        sb.append("REZULTATI:\n");
        results.forEach((opt, cnt) -> sb.append("  ").append(opt).append(": ").append(cnt).append("\n"));
        sb.append("\nNevazecih glasova: ").append(invalidVotes).append("\n");

        byte[] reportBytes = sb.toString().getBytes("UTF-8");

        // izvjestaj se potpisuje privatnim kljucem organizatora
        Signature signer = Signature.getInstance("SHA256withRSA", "BC");
        signer.initSign(orgPrivKey);
        signer.update(reportBytes);
        byte[] sig = signer.sign();

        byte[] combined = new byte[4 + reportBytes.length + sig.length];
        combined[0] = (byte)(reportBytes.length >> 24);
        combined[1] = (byte)(reportBytes.length >> 16);
        combined[2] = (byte)(reportBytes.length >> 8);
        combined[3] = (byte)(reportBytes.length);
        System.arraycopy(reportBytes, 0, combined, 4, reportBytes.length);
        System.arraycopy(sig, 0, combined, 4 + reportBytes.length, sig.length);

        return combined;
    }

    private X509Certificate findCertBySerial(BigInteger serial) {
        return regService.getUsers().values().stream()
                .filter(r -> r.certSerial.equals(serial))
                .findFirst()
                .map(r -> {
                    try {
                        // rekonstrukcija x509cert iz der bajtova
                        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                        return (X509Certificate) cf.generateCertificate(
                                new ByteArrayInputStream(r.encodedCertificate));
                    } catch (Exception e) {
                        System.out.println("[!] Greška pri učitavanju certa: " + e.getMessage());
                        return null;
                    }
                })
                .orElse(null);
    }

    private Poll getPollOrThrow(String pollId) {
        Poll p = polls.get(pollId);
        if (p == null)
            throw new NoSuchElementException("Glasanje nije pronadjeno: " + pollId);
        return p;
    }

    // derivira hmac kljuc iz privatnog rsa kljuca
    private byte[] deriveHmacKey(PrivateKey privKey) throws Exception{
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
        // vraca pkcs8 oblik privatnog kljuca
        return sha256.digest(privKey.getEncoded());
    }

    // serijalizuje metapodatke glasanja u bajtove za hmac
    private byte[] buildMetadataBytes(String pollId, String title, List<String> options, Instant start, Instant end) {
        String s = pollId + "|" + title + "|" + String.join(",", options) + "|" + start.toEpochMilli() + "|" + end.toEpochMilli();
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // racuna hmac sha256
    private byte[] computeHmac(byte[] data, byte[] key) throws Exception {
        // hmac sa sha256 hash funkcijom
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        // pakuje sirove bajtove u secretkey objekat koji mac ocekuje
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
