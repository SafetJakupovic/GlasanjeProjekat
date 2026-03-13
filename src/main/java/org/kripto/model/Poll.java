package org.kripto.model;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

// glasanje koje kreira organizator
public class Poll implements Serializable {
    public enum Status {
        PENDING,
        ACTIVE,
        CLOSED,
        COUNTED
    }

    public static final long serialVersionUID = 1L;
    public final String id;
    public final String organizerUsername;
    public final String title;
    public final String description;
    public final Instant startTime;
    public final Instant endTime;

    // lista opcija za glasanje
    public final List<String> options;

    // lista glasova
    private final List<Vote> votes = new ArrayList<>();

    // hmac zastita metapodataka
    public final byte[] metadataHmac;

    // rezultati
    // popunjeni tek nakon brojanja
    private Map<String, Integer> results = null;

    // digitalno potpisan izvjestaj
    // isto nakon brojanja
    private byte[] signedReport = null;

    public Poll(String id, String organizerName, String title, String description, Instant startTime, Instant endTime, List<String> options, byte[] metadataHmac) {
        if(options.size() < 2 || options.size() > 5)
            throw new IllegalArgumentException("Broj opcija mora biti izmedju 2 i 5");
        this.id = id;
        this.organizerUsername = organizerName;
        this.title = title;
        this.description = description;
        this.startTime = startTime;
        this.endTime = endTime;
        this.options = options;
        this.metadataHmac = metadataHmac;
    }

    public Status getStatus() {
        Instant now = Instant.now();
        if (now.isBefore(startTime))
            return Status.PENDING;
        if (now.isAfter(endTime))
            return results != null ? Status.COUNTED : Status.CLOSED;
        return Status.ACTIVE;
    }

    public void addVote(Vote vote) {
        if (getStatus() != Status.ACTIVE)
            throw new IllegalArgumentException("Glasanje nije aktivno");

        boolean alreadyVoted = votes.stream()
                .anyMatch(v -> v.voterCertSerial.equals(vote.voterCertSerial));
        if (alreadyVoted)
            throw new IllegalArgumentException("Glasac je vec glasao u ovom glasanju");
        votes.add(vote);
    }

    public boolean hasVoted(BigInteger voterCertSerial) {
        return votes.stream()
                .anyMatch(vote -> vote.voterCertSerial.equals(voterCertSerial));
    }

    public List<Vote> getVotes() {
        return List.copyOf(votes);
    }

    public Optional<Vote> findVoteById(String voteId) {
        return votes.stream()
                .filter(v -> v.voteId.equals(voteId)).findFirst();
    }

    public void setResults(Map<String, Integer> results) {
        this.results = results;
    }

    public Map<String, Integer> getResults() {
        return results;
    }

    public void setSignedReport(byte[] report) {
        this.signedReport = report;
    }

    public byte[] getSignedReport() {
        return signedReport;
    }

    @Override
    public String toString() {
        ZoneId zone = ZoneId.systemDefault();
        String start = startTime.atZone(zone).toLocalDateTime()
                .format(java.time.format.DateTimeFormatter.ofPattern("dd.MM.yyyy. HH:mm"));
        String end = endTime.atZone(zone).toLocalDateTime()
                .format(java.time.format.DateTimeFormatter.ofPattern("dd.MM.yyyy. HH:mm"));
        return String.format("[%s] %s | %s → %s | Status: %s | Glasova: %d",
                id, title, start, end, getStatus(), votes.size());
    }
}
