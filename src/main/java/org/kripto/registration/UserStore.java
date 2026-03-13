package org.kripto.registration;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class UserStore {
    private static final String USERS_PATH = "data/users.ser";

    /**
     * Čuva mapu korisnika na disk.
     */
    public static void save(Map<String, RegistrationService.UserRecord> users) throws Exception {
        new File("data").mkdirs();
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(USERS_PATH))) {
            oos.writeObject(new HashMap<>(users));
        }
    }

    /**
     * Učitava mapu korisnika sa diska.
     * Vraća praznu mapu ako fajl ne postoji.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, RegistrationService.UserRecord> load() throws Exception {
        File f = new File(USERS_PATH);
        if (!f.exists()) return new HashMap<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            return (Map<String, RegistrationService.UserRecord>) ois.readObject();
        }
    }

}
