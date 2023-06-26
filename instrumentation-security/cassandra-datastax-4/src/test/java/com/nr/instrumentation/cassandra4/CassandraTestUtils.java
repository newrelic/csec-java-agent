package com.nr.instrumentation.cassandra4;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class CassandraTestUtils {
    static Map<String, String> getBoundParams () {
        Map<String, String> params = new HashMap<>();
        params.put("0", UUID.randomUUID().toString());
        params.put("1", "idawda@gmail.com");
        params.put("2", String.valueOf(22));
        params.put("3", String.valueOf(false));
        params.put("5", String.valueOf(new BigDecimal(22222222)));
        params.put("6", String.valueOf(LocalDate.of(2000,1,1)));
        params.put("7", "ishi");
        params.put("8", String.valueOf(new ArrayList<>()));
        params.put("9", String.valueOf(new HashSet<>()));
        params.put("10", String.valueOf(new HashMap<>()));
        return params;
    }
    static Map<String, String> getValueParams() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "bob1@example.com");
        return params;
    }

    static Map<String, String> getNamedParams() {
        Map<String, String> params = new HashMap<>();
        params.put("email", "bob1@example.com");
        return params;
    }

    static List<String> getQueries() {
        List<String> QUERIES = new ArrayList<>();

        QUERIES.add("INSERT INTO users (age, email) VALUES (35, 'bob@example.com')");
        QUERIES.add("INSERT INTO users (email,age) VALUES (?,?)");
        QUERIES.add("INSERT INTO users (email,age) VALUES (:email,:age)");
        QUERIES.add("INSERT INTO users2 (id, email, age, isMarried, img, phone, dob, name, events, address, marks) VALUES (?,?,?,?,?,?,?,?,?,?,?)");

        QUERIES.add("SELECT * FROM users WHERE email=?");
        QUERIES.add("SELECT * FROM users WHERE email=:email");
        QUERIES.add("SELECT * FROM users");

        QUERIES.add("DELETE FROM users WHERE email=?");
        QUERIES.add("DELETE FROM users WHERE email=:email");

        QUERIES.add("UPDATE users SET age=? WHERE email=?");
        QUERIES.add("UPDATE users SET age=:age WHERE email=:email");
        return QUERIES;
    }
}
