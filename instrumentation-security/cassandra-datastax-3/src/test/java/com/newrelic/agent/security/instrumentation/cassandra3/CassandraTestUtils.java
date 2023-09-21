package com.newrelic.agent.security.instrumentation.cassandra3;

import com.datastax.driver.core.DataType;
import com.datastax.driver.core.LocalDate;
import com.datastax.driver.core.ProtocolVersion;
import com.datastax.driver.core.Statement;
import com.datastax.driver.core.StatementWrapper;
import com.datastax.driver.core.TypeCodec;
import com.datastax.driver.core.exceptions.InvalidTypeException;
import org.joda.time.DateTime;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class CassandraTestUtils {
    private static final String KEYSPACE = "test";
    static Map<String, String> getBoundParams () {
        Map<String, String> params = new HashMap<>();
        params.put("0", UUID.randomUUID().toString());
        params.put("1", "idawda@gmail.com");
        params.put("2", String.valueOf(22));
        params.put("3", String.valueOf(false));
        params.put("5", String.valueOf(new BigDecimal(22222222)));
        params.put("6", String.valueOf(LocalDate.fromDaysSinceEpoch(100)));
        params.put("7", "ishi");
        params.put("8", String.valueOf(new ArrayList<>()));
        params.put("9", String.valueOf(new HashSet<>()));
        params.put("10", String.valueOf(new HashMap<>()));
        return params;
    }
    static Map<String, String> getValueParams() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "35");
        params.put("1", "bob1@example.com");
        return params;
    }

    static Map<String, String> getNamedParams() {
        Map<String, String> params = new HashMap<>();
        params.put("age", "35");
        params.put("email", "bob1@example.com");
        return params;
    }
    static Map<String, String> getCustomCodecParams() {
        Map<String, String> params = new HashMap<>();
        params.put("0", String.valueOf(UUID.randomUUID()));
        params.put("1", String.valueOf(DateTime.now()));
        return params;
    }
    static List<String> getQueries(){
        List<String> QUERIES = new ArrayList<>();
        // SCHEMA BASED QUERIES
        QUERIES.add("CREATE KEYSPACE " + KEYSPACE + " WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };");
        QUERIES.add("USE " + KEYSPACE + ";");
        QUERIES.add("CREATE TABLE users (email text, age int, PRIMARY KEY (email));");
        QUERIES.add("CREATE TABLE users2 (id uuid PRIMARY KEY, email text, age int, isMarried boolean, img blob, phone decimal, dob DATE, name varchar, events list<text>, address set<text>, marks map<text,int>);");

        // QUERIES FOR TABLE, index starts from 4
        QUERIES.add("INSERT INTO users (age, email) VALUES (35, 'bob@example.com')");
        QUERIES.add("INSERT INTO users (age, email) VALUES (?, ?)");
        QUERIES.add("INSERT INTO users (age, email) VALUES (:age, :email)");
        QUERIES.add("INSERT INTO users2 (id, email, age, isMarried, img, phone, dob, name, events, address, marks) VALUES (?,?,?,?,?,?,?,?,?,?,?)");

        // QUERY for creating a table with custom codec DateTimeCodec
        QUERIES.add("CREATE TABLE users3 (id uuid PRIMARY KEY, timestamp TIMESTAMP);");
        QUERIES.add("INSERT INTO users3 (id, timestamp) VALUES (?, ?)");
        QUERIES.add("INSERT INTO users (age,email) VALUES (35,?)");
        QUERIES.add("BEGIN BATCH INSERT INTO users (email,age) VALUES (?,30);UPDATE users SET age=50 WHERE email=?;APPLY BATCH;");
        QUERIES.add("SELECT * FROM users WHERE email=?");
        QUERIES.add("DELETE FROM users WHERE email=?");
        QUERIES.add("UPDATE users SET age=50 WHERE email=?");
        return QUERIES;
    }

    static class SimpleStatementWrapper extends StatementWrapper {
        public SimpleStatementWrapper(Statement statement) {
            super(statement);
        }
    }
    static class DateTimeCodec extends TypeCodec<DateTime> {
        public DateTimeCodec() {
            super(DataType.timestamp(), DateTime.class);
        }
        @Override
        public DateTime parse(String value) {
            if (value == null || value.equals("NULL")) return null;
            try {
                return DateTime.parse(value);
            } catch (IllegalArgumentException iae) {
                throw new InvalidTypeException("Could not parse format: " + value, iae);
            }
        }
        @Override
        public String format(DateTime value) {
            if (value == null)
                return "NULL";
            return Long.toString(value.getMillis());
        }
        @Override
        public ByteBuffer serialize(DateTime value, ProtocolVersion protocolVersion) {
            return value == null ? null : TypeCodec.bigint().serialize(value.getMillis(), protocolVersion);
        }
        @Override
        public DateTime deserialize(ByteBuffer bytes, ProtocolVersion protocolVersion) {
            return bytes == null || bytes.remaining() == 0 ? null: new DateTime(TypeCodec.bigint().deserializeNoBoxing(bytes, protocolVersion));
        }
    }
}
