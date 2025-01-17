package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.schedulers.SchedulerHelper;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class TTLMap<K, V> {

        private final ConcurrentHashMap<K, V> map = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<K, Long> timestamps = new ConcurrentHashMap<>();
        private final long TTL;
        private final String id;

        public TTLMap(String id) {
            this(id, 300_000);// 5 minutes in milliseconds
        }

        public TTLMap(String id, long ttl) {
            this.id = id;
            TTL = ttl;
            SchedulerHelper.getInstance().scheduleTTLMapCleanup(this::removeExpiredEntries, ttl, ttl, TimeUnit.MILLISECONDS, id);
        }

        public void put(K key, V value) {
            map.put(key, value);
            timestamps.put(key, System.currentTimeMillis());
        }

        public V get(K key) {
            return map.get(key);
        }

        public void remove(K key) {
            map.remove(key);
            timestamps.remove(key);
        }

        private void removeExpiredEntries() {
            long now = System.currentTimeMillis();
            for (K key : timestamps.keySet()) {
                if (now - timestamps.get(key) >= TTL) {
                    map.remove(key);
                    timestamps.remove(key);
                }
            }
        }

        public void shutdown() {
            SchedulerHelper.getInstance().cancelTTLMapCleanup(this.id);
        }

        public boolean containsKey(K traceId) {
            return map.containsKey(traceId);
        }
}
