package com.nr.agent.security.instrumentation.jcache;

import com.hazelcast.cache.HazelcastCachingProvider;
import com.hazelcast.config.Config;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.JCacheOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.CompleteConfiguration;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.integration.CompletionListener;
import javax.cache.spi.CachingProvider;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "javax.cache" })
public class JCacheTest {
    private static final HazelcastInstance HAZELCAST_INSTANCE = Hazelcast.newHazelcastInstance(new Config()
            .addMapConfig(new MapConfig("default")
            .setInMemoryFormat(InMemoryFormat.NATIVE)));
    private static CacheManager cacheManager;
    private static Cache<String, Object> cache;

    @AfterClass
    public static void tearDown() {
        if (cacheManager!=null && !cacheManager.isClosed()) {
            cacheManager.destroyCache("test");
            cacheManager.close();
        }
    }

    @Test
    public void testPutGet() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.put(key, val);
        cache.get(key);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 2, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "put", "write");
        verifier((JCacheOperation) operations.get(1), Collections.singletonList(key), "get", "read");
    }

    @Test
    public void testPutGetObject() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        CustomObject val = new CustomObject(uuid, 123);
        cache.put(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "put", "write");
    }

    @Test
    public void testPutAllGetAll() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.putAll(Collections.singletonMap(key, val));
        cache.getAll(Collections.singleton(key));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 2, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "putAll", "write");
        verifier((JCacheOperation) operations.get(1), Collections.singletonList(key), "getAll", "read");
    }

    @Test
    public void testContainsKey() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        cache.containsKey(key);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Collections.singletonList(key), "containsKey", "read");
    }

    @Test
    public void testLoadAll() {
        String key = "key-";
        String val = "value-";
        cache.loadAll(new HashSet<String>(){{ add(key); add(val); }}, true, new CompletionListener() {
            @Override
            public void onCompletion() {

            }

            @Override
            public void onException(Exception e) {

            }
        });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(val, key), "loadAll", "read");
    }

    @Test
    public void testGetAndPut() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.getAndPut(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "getAndPut", "write");
    }

    @Test
    public void testPutIfAbsent() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.putIfAbsent(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "putIfAbsent", "write");
    }

    @Test
    public void testRemove() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        cache.remove(key);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Collections.singletonList(key), "remove", "delete");
    }

    @Test
    public void testRemove2() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.remove(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "remove", "delete");
    }

    @Test
    public void testGetAndRemove() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        cache.getAndRemove(key);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Collections.singletonList(key), "getAndRemove", "delete");
    }

    @Test
    public void testReplace() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.replace(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "replace", "update");
    }

    @Test
    public void testReplace2() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.replace(key, val, "test");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val, "test"), "replace", "update");
    }

    @Test
    public void testGetAndReplace() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        String val = "value-"+uuid;
        cache.getAndReplace(key, val);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Arrays.asList(key, val), "getAndReplace", "update");
    }

    @Test
    public void testRemoveAll() {
        String uuid = UUID.randomUUID().toString();
        String key = "key-"+uuid;
        cache.removeAll(Collections.singleton(key));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Incorrect number operations detected", 1, operations.size());

        verifier((JCacheOperation) operations.get(0), Collections.singletonList(key), "removeAll", "delete");
    }

    @Test
    public void testRemoveAll2() {
        cache.removeAll();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertEquals("Unexpected operations detected", 0, operations.size());
    }

    private static void verifier(JCacheOperation operation, List<Object> args, String method, String type) {
        Assert.assertEquals("Incorrect case type.", VulnerabilityCaseType.CACHING_DATA_STORE, operation.getCaseType());
        Assert.assertEquals("Incorrect event category.", JCacheOperation.JCACHE, operation.getCategory());
        Assert.assertEquals("Incorrect command type.", type, operation.getType());
        Assert.assertEquals("Incorrect executed method name.", method, operation.getMethodName());
        Assert.assertEquals("Incorrect parameters", args, operation.getArguments());
    }

    @BeforeClass
    public static void getManagerCache() {
        CachingProvider provider = Caching.getCachingProvider("com.hazelcast.cache.HazelcastMemberCachingProvider");
        cacheManager = provider.getCacheManager(null, null, HazelcastCachingProvider.propertiesByInstanceItself(HAZELCAST_INSTANCE));
        CompleteConfiguration<String, Object> config = new MutableConfiguration<String, Object>().setTypes( String.class, Object.class );
        cache = cacheManager.createCache("test", config);
    }
}
