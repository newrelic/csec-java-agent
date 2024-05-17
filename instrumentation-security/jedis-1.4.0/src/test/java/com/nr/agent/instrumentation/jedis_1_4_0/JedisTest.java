package com.nr.agent.instrumentation.jedis_1_4_0;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RedisOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import redis.clients.jedis.BinaryClient;
import redis.clients.jedis.Client;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPubSub;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.Transaction;
import redis.embedded.RedisServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "redis.clients.jedis")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JedisTest {
    private static int PORT = 0;

    public static GenericContainer<?> redis;

    @BeforeClass
    public static void setup() {
        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        redis = new GenericContainer<>(DockerImageName.parse("redis:5.0.3-alpine"));
        redis.setPortBindings(Collections.singletonList(PORT + ":6379"));
        redis.start();
    }
    @AfterClass
    public static void tearDown() {
        redis.stop();
    }

    @Test
    public void testSet_Get_Exists_Del() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.set(keyValuePair.getKey(), keyValuePair.getValue());
        jedis.exists(keyValuePair.getKey());
        jedis.get(keyValuePair.getKey());
        jedis.del(keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.SET, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.EXISTS, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.GET, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.DEL, operation, Collections.singletonList(keyValuePair.getKey()));
    }

    @Test
    public void testSetnx_Setex() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.setnx(keyValuePair.getKey(), keyValuePair.getValue());
        jedis.setex(keyValuePair.getKey(), 30, keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.SETNX, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.SETEX, operation, Arrays.asList(keyValuePair.getKey(), "30", keyValuePair.getValue()));
    }

    @Test
    public void testMsetnx() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.msetnx(keyValuePair.getKey(), keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.MSETNX, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));
    }

    @Test
    public void testHsetnx() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.hsetnx(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.HSETNX, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));
    }

    @Test
    public void testHset_Hexists_Hget_Hlen_Hgetall_Hkeys_Hvals_Hdel() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.hset(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue());
        jedis.hexists(keyValuePair.getHash(), keyValuePair.getKey());
        jedis.hget(keyValuePair.getHash(), keyValuePair.getKey());
        jedis.hlen(keyValuePair.getKey());
        jedis.hgetAll(keyValuePair.getKey());
        jedis.hkeys(keyValuePair.getHash());
        jedis.hvals(keyValuePair.getHash());
        jedis.hdel(keyValuePair.getHash(), keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 8);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.HSET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.HEXISTS, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.HGET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.HLEN, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(4);
        verifier(Protocol.Command.HGETALL, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(5);
        verifier(Protocol.Command.HKEYS, operation, Collections.singletonList(keyValuePair.getHash()));

        operation = (RedisOperation) operations.get(6);
        verifier(Protocol.Command.HVALS, operation, Collections.singletonList(keyValuePair.getHash()));

        operation = (RedisOperation) operations.get(7);
        verifier(Protocol.Command.HDEL, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));
    }

    @Test
    public void testMset_Mget() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.mset(keyValuePair.getKey(), keyValuePair.getValue());
        jedis.mget(keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.MSET, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.MGET, operation, Collections.singletonList(keyValuePair.getKey()));
    }

    @Test
    public void testHmset_Hmget() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.hmset(keyValuePair.getHash(), Collections.singletonMap(keyValuePair.getKey(), keyValuePair.getValue()));
        jedis.hmget(keyValuePair.getHash(), keyValuePair.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.HMSET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.HMGET, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey()));
    }

    @Test
    public void testIncr_IncrBy_Decr_DecrBy() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.incr(keyValuePair.getKey());
        jedis.incrBy(keyValuePair.getKey(), 201);
        jedis.decr(keyValuePair.getKey());
        jedis.decrBy(keyValuePair.getKey(), 201);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.INCR, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.INCRBY, operation, Arrays.asList(keyValuePair.getKey(), "201"));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.DECR, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.DECRBY, operation, Arrays.asList(keyValuePair.getKey(), "201"));
    }

    @Test
    public void testHincrBy() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.hincrBy(keyValuePair.getHash(), keyValuePair.getKey(), 201);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 1);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.HINCRBY, operation, Arrays.asList(keyValuePair.getHash(), keyValuePair.getKey(), "201"));
    }

    @Test
    public void testLpush_Llen_Linsert_Lindex_Lpop_Lrem() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.lpush(keyValuePair.getKey(), keyValuePair.getValue());
        jedis.llen(keyValuePair.getKey());
        jedis.linsert(keyValuePair.getKey(), BinaryClient.LIST_POSITION.AFTER, "0", keyValuePair.getValue());
        jedis.lindex(keyValuePair.getKey(), 0);
        jedis.lpop(keyValuePair.getKey());
        jedis.lrem(keyValuePair.getKey(), 1, keyValuePair.getValue());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 6);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.LPUSH, operation, Arrays.asList(keyValuePair.getKey(), keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.LLEN, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.LINSERT, operation, Arrays.asList(keyValuePair.getKey(), "AFTER", "0", keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.LINDEX, operation, Arrays.asList(keyValuePair.getKey(), "0"));

        operation = (RedisOperation) operations.get(4);
        verifier(Protocol.Command.LPOP, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(5);
        verifier(Protocol.Command.LREM, operation, Arrays.asList(keyValuePair.getKey(), "1", keyValuePair.getValue()));
    }

    @Test
    public void testZadd_Zcard_Zcount_Zincrby_Zrange_Zrem() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.zadd(keyValuePair.getKey(), 2, keyValuePair.getValue());
        jedis.zcard(keyValuePair.getKey());
        jedis.zcount(keyValuePair.getKey(), 0, 2);
        jedis.zincrby(keyValuePair.getKey(), 1, "201");
        jedis.zrange(keyValuePair.getKey(), 0, 1);
        jedis.zrem(keyValuePair.getKey(), "1");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 6);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.ZADD, operation, Arrays.asList(keyValuePair.getKey(), "2.0", keyValuePair.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.ZCARD, operation, Collections.singletonList(keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.ZCOUNT, operation, Arrays.asList(keyValuePair.getKey(), "0.0", "2.0"));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.ZINCRBY, operation, Arrays.asList(keyValuePair.getKey(), "1.0", "201"));

        operation = (RedisOperation) operations.get(4);
        verifier(Protocol.Command.ZRANGE, operation, Arrays.asList(keyValuePair.getKey(), "0", "1"));

        operation = (RedisOperation) operations.get(5);
        verifier(Protocol.Command.ZREM, operation, Arrays.asList(keyValuePair.getKey(), "1"));
    }

    @Test
    public void testExpire_Expireat() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.set(keyValuePair.getKey(), keyValuePair.getValue());
        jedis.expire(keyValuePair.getKey(), 30);
        long unixTime = System.currentTimeMillis() + 3000;
        jedis.expireAt(keyValuePair.getKey(), unixTime);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 3);

        RedisOperation operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.EXPIRE, operation, Arrays.asList(keyValuePair.getKey(), "30"));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.EXPIREAT, operation, Arrays.asList(keyValuePair.getKey(), String.valueOf(unixTime)));
    }

    @Test
    public void testMulti_Move_Smove_Substr_Exec() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        Transaction transaction = jedis.multi();
        transaction.move(keyValuePair1.getKey(), 1);
        transaction.smove(keyValuePair1.getKey(), keyValuePair2.getKey(), "member");
        transaction.substr(keyValuePair1.getKey(), 0,2);
        transaction.exec();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 3);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.MOVE, operation, Arrays.asList(keyValuePair1.getKey(), "1"));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.SMOVE, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey(), "member"));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.SUBSTR, operation, Arrays.asList(keyValuePair1.getKey(), "0", "2"));
    }

    @Test
    public void testPing_Sync_Flushdb_quit() {
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.ping();
        jedis.sync();
        jedis.flushDB();
        jedis.quit();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertEquals("Operations detected but was not expecting any.", 0, operations.size());
    }

    @Test
    public void testSubscribe_Publish() throws InterruptedException, IOException {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis1 = new Jedis("localhost", PORT);
        Jedis jedis2 = new Jedis("localhost", PORT);

        jedis1.connect();

        final JedisPubSub jedisPubSub = new JedisPubSub() {
            @Override
            public void onUnsubscribe(String channel, int subscribedChannels) {
            }

            @Override
            public void onSubscribe(String channel, int subscribedChannels) {
            }

            @Override
            public void onPUnsubscribe(String pattern, int subscribedChannels) {
            }

            @Override
            public void onPSubscribe(String pattern, int subscribedChannels) {
            }

            @Override
            public void onPMessage(String pattern, String channel, String message) {
            }

            @Override
            public void onMessage(String channel, String message) {
                System.out.println(message);
            }
        };
        new Thread(new Runnable() {
            @Override
            public void run() {
                jedis1.subscribe(jedisPubSub, "testing");
                jedis1.quit();
            }
        }, "subscriberThread").start();

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                }
                jedis2.publish("testing", keyValuePair.getValue());
                jedis2.quit();
            }
        }, "publisherThread").start();

        Thread.sleep(2000);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.SUBSCRIBE, operation, Collections.singletonList("testing"));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.PUBLISH, operation, Arrays.asList("testing", keyValuePair.getValue()));
    }

    @Test
    public void testPsubscribe_Publish() throws InterruptedException, IOException {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis1 = new Jedis("localhost", PORT);
        Jedis jedis2 = new Jedis("localhost", PORT);

        jedis1.connect();

        final JedisPubSub jedisPubSub = new JedisPubSub() {
            @Override
            public void onUnsubscribe(String channel, int subscribedChannels) {
            }

            @Override
            public void onSubscribe(String channel, int subscribedChannels) {
            }

            @Override
            public void onPUnsubscribe(String pattern, int subscribedChannels) {
            }

            @Override
            public void onPSubscribe(String pattern, int subscribedChannels) {
            }

            @Override
            public void onPMessage(String pattern, String channel, String message) {
            }

            @Override
            public void onMessage(String channel, String message) {
                System.out.println(message);
            }
        };
        new Thread(new Runnable() {
            @Override
            public void run() {
                jedis1.psubscribe(jedisPubSub, "t*sting");
                jedis1.quit();
            }
        }, "pSubscriberThread").start();

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                }
                jedis2.publish("testing", keyValuePair.getKey());
                jedis2.publish("txsting", keyValuePair.getValue());
                jedis2.quit();
            }
        }, "pPublisherThread").start();

        Thread.sleep(2000);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 3);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.PSUBSCRIBE, operation, Collections.singletonList("t*sting"));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.PUBLISH, operation, Arrays.asList("testing", keyValuePair.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.PUBLISH, operation, Arrays.asList("txsting", keyValuePair.getValue()));
    }

    @Test
    public void testGetSet_Append() {
        KeyValuePair keyValuePair = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.getSet(keyValuePair.getKey(), "test");
        jedis.append(keyValuePair.getKey(), "done");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 2);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.GETSET, operation, Arrays.asList(keyValuePair.getKey(), "test"));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.APPEND, operation, Arrays.asList(keyValuePair.getKey(), "done"));
    }

    @Test
    public void testRpush_Rpushx_Rpop_Rpoplpush() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.rpush(keyValuePair1.getKey(), keyValuePair1.getValue());
        jedis.rpushx(keyValuePair2.getKey(), keyValuePair2.getValue());
        jedis.rpop(keyValuePair1.getKey());
        jedis.rpoplpush(keyValuePair2.getKey(), keyValuePair1.getKey());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 4);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.RPUSH, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair1.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.RPUSHX, operation, Arrays.asList(keyValuePair2.getKey(), keyValuePair2.getValue()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.RPOP, operation, Collections.singletonList(keyValuePair1.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.RPOPLPUSH, operation, Arrays.asList(keyValuePair2.getKey(), keyValuePair1.getKey()));
    }

    @Test
    public void testSadd_Sdiff_Scard_Smove_Srem() {
        KeyValuePair keyValuePair1 = KeyValuePair.getKeyValuePair();
        KeyValuePair keyValuePair2 = KeyValuePair.getKeyValuePair();
        Jedis jedis = new Jedis("localhost", PORT);

        jedis.sadd(keyValuePair1.getKey(), keyValuePair1.getValue());
        jedis.sdiff(keyValuePair1.getKey(), keyValuePair2.getKey());
        jedis.scard(keyValuePair1.getKey());
        jedis.smove(keyValuePair1.getKey(), keyValuePair2.getKey(), "test");
        jedis.srem(keyValuePair1.getKey(), "test");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        opVerifier(operations, 5);

        RedisOperation operation = (RedisOperation) operations.get(0);
        verifier(Protocol.Command.SADD, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair1.getValue()));

        operation = (RedisOperation) operations.get(1);
        verifier(Protocol.Command.SDIFF, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey()));

        operation = (RedisOperation) operations.get(2);
        verifier(Protocol.Command.SCARD, operation, Collections.singletonList(keyValuePair1.getKey()));

        operation = (RedisOperation) operations.get(3);
        verifier(Protocol.Command.SMOVE, operation, Arrays.asList(keyValuePair1.getKey(), keyValuePair2.getKey(), "test"));

        operation = (RedisOperation) operations.get(4);
        verifier(Protocol.Command.SREM, operation, Arrays.asList(keyValuePair1.getKey(), "test"));
    }
    private static void opVerifier(List<AbstractOperation> operations, int expected) {
        Assert.assertTrue("No operations detected.", operations.size() > 0);
        Assert.assertEquals("Unexpected number of operations detected.", expected, operations.size());
    }

    private static void verifier(Protocol.Command cmd, RedisOperation operation, List<String> keyValuePair) {
        Assert.assertEquals(String.format("[%s] Invalid Command.", cmd), cmd.toString(), operation.getType());
        Assert.assertEquals(String.format("[%s] Invalid Category.", cmd), RedisOperation.REDIS, operation.getCategory());
        Assert.assertEquals(String.format("[%s] Invalid executed parameters.", cmd), keyValuePair, operation.getArguments());
        Assert.assertEquals(String.format("[%s] Invalid event category.", cmd), VulnerabilityCaseType.CACHING_DATA_STORE, operation.getCaseType());
        Assert.assertEquals(String.format("[%s] Invalid executed class name.", cmd), Client.class.getName(), operation.getClassName());
        Assert.assertEquals(String.format("[%s] Invalid executed method name.", cmd), "sendCommand", operation.getMethodName());
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
}
