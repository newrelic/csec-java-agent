package com.k2cybersecurity.intcodeagent.monitoring;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpConnectionStat;
import com.k2cybersecurity.intcodeagent.models.javaagent.OutBoundHttp;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class InBoundOutBoundST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();

    private ScheduledExecutorService inOutExecutorService;

    private static InBoundOutBoundST instance;

    private Map<Integer, OutBoundHttp> cache;

    private Set<OutBoundHttp> newConnections;

    public Map<Integer, OutBoundHttp> getCache() {
        return cache;
    }

    public Set<OutBoundHttp> getNewConnections() {
        return newConnections;
    }

    public boolean addOutBoundHTTPConnection(OutBoundHttp outBoundHttp) {
        if (getCache().containsKey(outBoundHttp.getHashCode())) {
            OutBoundHttp cachedHttpCon = cache.get(outBoundHttp.getHashCode());
            cachedHttpCon.getCount().incrementAndGet();
            return false;
        } else {
            cache.put(outBoundHttp.getHashCode(), outBoundHttp);
            return newConnections.add(outBoundHttp);
        }
    }

    private InBoundOutBoundST() {
        inOutExecutorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-inbound-outbound-st");
            }
        });
        inOutExecutorService.scheduleAtFixedRate(runnable, 2, 2, TimeUnit.HOURS);
        cache = new HashMap<>();
        newConnections = new HashSet<>();
        logger.log(LogLevel.INFO, "in-bound out-bound monitor thread started successfully!!!", InBoundOutBoundST.class.getName());
    }

    public static InBoundOutBoundST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new InBoundOutBoundST();
                }
            }
        }
        return instance;
    }

    private Runnable runnable = new Runnable() {

        @Override
        public void run() {

            /**
             * Create JSON
             * Send to IC
             * Clear cache
             * */
            HttpConnectionStat httpConnectionStat = new HttpConnectionStat(cache.values(), K2Instrumentator.APPLICATION_UUID, true);
            EventSendPool.getInstance().sendEvent(httpConnectionStat.toString());
            cache.clear();
        }
    };


    public void clearNewConnections() {
        newConnections.clear();
    }
}
