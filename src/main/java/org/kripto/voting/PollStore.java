package org.kripto.voting;

import org.kripto.model.Poll;

import java.io.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class PollStore {
    private static final String POLLS_PATH = "data/polls.ser";

    public static void save(Map<String, Poll> polls) throws Exception {
        new File("data").mkdirs();
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(POLLS_PATH))) {
            oos.writeObject(new LinkedHashMap<>(polls));
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Poll> load() throws Exception {
        File f = new File(POLLS_PATH);
        if (!f.exists()) return new LinkedHashMap<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            return (Map<String, Poll>) ois.readObject();
        }
    }
}
