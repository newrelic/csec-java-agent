package com.nr.agent.instrumentation.lettuce_5;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RedisOperation;
import io.lettuce.core.RedisAsyncCommandsImpl;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.protocol.CommandType;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import redis.embedded.RedisServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "io.lettuce.core")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LettuceTest {
    private static RedisServer redisServer;
    private static int PORT = 0;

    @BeforeClass
    public static void setup() throws Exception {
        PORT = getRandomPort();
        redisServer = new RedisServer(PORT);
        redisServer.start();
        System.out.println(redisServer);
    }

    @Test
    public void testSet_Get_Exists_Del() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();
        syncCommands.set(keyValuePair.getKey(), keyValuePair.getValue());
        syncCommands.exists(keyValuePair.getKey());
        syncCommands.get(keyValuePair.getKey());
        syncCommands.del(keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.SET, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.EXISTS, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.GET, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.DEL, operation, Collections.singletonList(keyValuePair.getKey()));
    }

    @Test
    public void testSetnx_Setex() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.setnx(keyValuePair.getKey(), keyValuePair.getValue());
        syncCommands.setex(keyValuePair.getKey(), 30, keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.SETNX, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.SETEX, operation, Arrays.asList(keyValuePair.getKey(), 30l, keyValuePair.getValue()));
    }

    @Test
    public void testMsetnx() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.msetnx(Collections.singletonMap(keyValuePair.getKey(), keyValuePair.getValue()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.MSETNX, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));
    }

    @Test
    public void testHsetnx() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.hsetnx(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.HSETNX, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));
    }

    @Test
    public void testHset_Hexists_Hget_Hlen_Hgetall_Hkeys_Hvals_Hdel() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.hset(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue());
        syncCommands.hexists(keyValuePair.getHash(), keyValuePair.getKey());
        syncCommands.hget(keyValuePair.getHash(), keyValuePair.getKey());
        syncCommands.hlen(keyValuePair.getKey());
        syncCommands.hgetall(keyValuePair.getKey());
        syncCommands.hkeys(keyValuePair.getHash());
        syncCommands.hvals(keyValuePair.getHash());
        syncCommands.hdel(keyValuePair.getHash(), keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 8);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.HSET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.HEXISTS, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.HGET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.HLEN, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(4);
        verifier(CommandType.HGETALL, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(5);
        verifier(CommandType.HKEYS, operation, Collections.singletonList(keyValuePair.getHash()));

        operation = (RedisOperation) operations.get(6);
        verifier(CommandType.HVALS, operation, Collections.singletonList(keyValuePair.getHash()));

        operation = (RedisOperation) operations.get(7);
        verifier(CommandType.HDEL, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));
    }

    @Test
    public void testMset_Mget() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.mset(Collections.singletonMap(keyValuePair.getKey(), keyValuePair.getValue()));
        syncCommands.mget(keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.MSET, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.MGET, operation, Collections.singletonList(keyValuePair.getKey()));
    }

    @Test
    public void testHmset_Hmget() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.hmset(keyValuePair.getHash(), Collections.singletonMap(keyValuePair.getKey(), keyValuePair.getValue()));
        syncCommands.hmget(keyValuePair.getHash(), keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.HMSET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.HMGET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));
    }

    @Test
    public void testIncr_IncrBy_Decr_DecrBy() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.incr(keyValuePair.getKey());
        syncCommands.incrby(keyValuePair.getKey(), 201);
        syncCommands.decr(keyValuePair.getKey());
        syncCommands.decrby(keyValuePair.getKey(), 201);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.INCR, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.INCRBY, operation, Arrays.asList(keyValuePair.getKey(), 201l));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.DECR, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.DECRBY, operation, Arrays.asList(keyValuePair.getKey(), 201l));
    }

    @Test
    public void testHincrBy() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.hincrby(keyValuePair.getHash(), keyValuePair.getKey(), 201);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.HINCRBY, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), 201l));
    }

    @Test
    public void testLpush_Llen_Linsert_Lindex_Lpop_Lrem() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.lpush(keyValuePair.getKey(), keyValuePair.getValue());
        syncCommands.llen(keyValuePair.getKey());
        syncCommands.linsert(keyValuePair.getKey(), true, "0", keyValuePair.getValue());
        syncCommands.lindex(keyValuePair.getKey(), 0);
        syncCommands.lpop(keyValuePair.getKey());
        syncCommands.lrem(keyValuePair.getKey(), 1, keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 6);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.LPUSH, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.LLEN, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.LINSERT, operation, Arrays.asList(keyValuePair.getKey(), "BEFORE", "0", keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.LINDEX, operation, Arrays.asList(keyValuePair.getKey(), 0l));

        operation = (RedisOperation) operations.get(4);
        verifier(CommandType.LPOP, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(5);
        verifier(CommandType.LREM, operation, Arrays.asList(keyValuePair.getKey(), 1l, keyValuePair.getValue()));
    }

    @Test
    public void testZadd_Zcard_Zcount_Zincrby_Zrange_Zrem() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.zadd(keyValuePair.getKey(), 2, keyValuePair.getValue());
        syncCommands.zcard(keyValuePair.getKey());
        syncCommands.zcount(keyValuePair.getKey(), 0, 2);
        syncCommands.zincrby(keyValuePair.getKey(), 1, "201");
        syncCommands.zrange(keyValuePair.getKey(), 0, 1);
        syncCommands.zrem(keyValuePair.getKey(), "1");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 6);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.ZADD, operation, Arrays.asList(keyValuePair.getKey(), 2.0d, keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.ZCARD, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.ZCOUNT, operation, Arrays.asList(keyValuePair.getKey(), "0.0", "2.0"));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.ZINCRBY, operation, Arrays.asList(keyValuePair.getKey(), 1.0d, "201"));

        operation = (RedisOperation) operations.get(4);
        verifier(CommandType.ZRANGE, operation, Arrays.asList(keyValuePair.getKey(), 0l, 1l));

        operation = (RedisOperation) operations.get(5);
        verifier(CommandType.ZREM, operation, Arrays.asList(keyValuePair.getKey(), "1"));
    }

    @Test
    public void testExpire_Expireat() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.set(keyValuePair.getKey(), keyValuePair.getValue());
        syncCommands.expire(keyValuePair.getKey(), 30);
        long unixTime = System.currentTimeMillis() + 3000;
        syncCommands.expireat(keyValuePair.getKey(), unixTime);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 3);

        RedisOperation operation = (RedisOperation) operations.get(1);
        verifier(CommandType.EXPIRE, operation, Arrays.asList(keyValuePair.getKey(), 30l));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.EXPIREAT, operation, Arrays.asList(keyValuePair.getKey(), unixTime));
    }

    @Test
    public void testMulti_Move_Smove_Substr_Exec() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.multi();
        syncCommands.smove(keyValuePair1.getKey(), keyValuePair2.getKey(), "member");
        syncCommands.exec();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.SMOVE, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey(), "member"));
    }

    @Test
    public void testPing_Quit_Flushdb() {
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.ping();
//        syncCommands.flushDB();
        syncCommands.quit();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertEquals("Operations detected but was not expecting any.", 0, operations.size());
    }

    @Test
    public void testGetSet_Append() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.getset(keyValuePair.getKey(), "test");
        syncCommands.append(keyValuePair.getKey(), "done");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.GETSET, operation, Arrays.asList(keyValuePair.getKey(), "test"));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.APPEND, operation, Arrays.asList(keyValuePair.getKey(), "done"));
    }

    @Test
    public void testRpush_Rpushx_Rpop_Rpoplpush() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.rpush(keyValuePair1.getKey(), keyValuePair1.getValue());
        syncCommands.rpushx(keyValuePair2.getKey(), keyValuePair2.getValue());
        syncCommands.rpop(keyValuePair1.getKey());
        syncCommands.rpoplpush(keyValuePair2.getKey(), keyValuePair1.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.RPUSH, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair1.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.RPUSHX, operation, Arrays.asList(keyValuePair2.getKey(), keyValuePair2.getValue()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.RPOP, operation, Collections.singletonList(keyValuePair1.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.RPOPLPUSH, operation, Arrays.asList(keyValuePair2.getKey(), keyValuePair1.getKey()));
    }

    @Test
    public void testSadd_Sdiff_Scard_Smove_Srem() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        RedisCommands<String, String> syncCommands = getStringStringRedisCommands();

        syncCommands.sadd(keyValuePair1.getKey(), keyValuePair1.getValue());
        syncCommands.sdiff(keyValuePair1.getKey(), keyValuePair2.getKey());
        syncCommands.scard(keyValuePair1.getKey());
        syncCommands.smove(keyValuePair1.getKey(), keyValuePair2.getKey(), "test");
        syncCommands.srem(keyValuePair1.getKey(), "test");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 5);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(CommandType.SADD, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair1.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(CommandType.SDIFF, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(CommandType.SCARD, operation, Collections.singletonList(keyValuePair1.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(CommandType.SMOVE, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey(), "test"));

        operation = (RedisOperation) operations.get(4);
        verifier(CommandType.SREM, operation, Arrays.asList(keyValuePair1.getKey(), "test"));
    }

    @AfterClass
    public static void tearDown() throws Exception {
        redisServer.stop();
    }

    private static void opVerifier(List<AbstractOperation> operations, int expected) {
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        Assert.assertEquals("Unexpected number of operations detected.", expected, operations.size());
    }

    private static void verifier(CommandType cmd, RedisOperation operation, List<Object> keyValuePair) {
        Assert.assertEquals(String.format("[%s] Invalid Command.", cmd), cmd.toString(), operation.getType());
        Assert.assertEquals(String.format("[%s] Invalid Category.", cmd), RedisOperation.REDIS, operation.getCategory());
        for(int i=0; i< keyValuePair.size(); i++) {
            if (operation.getArguments().get(i) instanceof byte[]){
                String val = new String((byte[]) operation.getArguments().get(i), StandardCharsets.UTF_8);
                Assert.assertEquals(String.format("[%s] Invalid executed parameter.", cmd), keyValuePair.get(i), val);
            } else {
                Assert.assertEquals(String.format("[%s] Invalid executed parameter.", cmd), keyValuePair.get(i), operation.getArguments().get(i));
            }
        }
        Assert.assertEquals(String.format("[%s] Invalid event category.", cmd), VulnerabilityCaseType.CACHING_DATA_STORE, operation.getCaseType());
        Assert.assertEquals(String.format("[%s] Invalid executed class name.", cmd), RedisAsyncCommandsImpl.class.getName(), operation.getClassName());
        Assert.assertEquals(String.format("[%s] Invalid executed method name.", cmd), "dispatch", operation.getMethodName());
    }

    private static int getRandomPort() {
        int port;

        try {
            ServerSocket socket = new ServerSocket(0);
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
        return port;
    }

    static class KeyValuePair {
        private String key;
        private String value;
        private String hash;

        public KeyValuePair(String key, String value, String hash) {
            this.key = key;
            this.value = value;
            this.hash = hash;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

        public String getHash() {
            return hash;
        }

        public static KeyValuePair getKeyValuePair(){
            UUID uuid = UUID.randomUUID();
            return new KeyValuePair("key-"+uuid, "101", uuid.toString());
        }
    }

    private static RedisCommands<String, String> getStringStringRedisCommands() {
        RedisClient redisClient = RedisClient.create("redis://localhost:"+PORT);
        StatefulRedisConnection<String, String> connection = redisClient.connect();

        RedisCommands<String, String> syncCommands = connection.sync();
        return syncCommands;
    }
}
