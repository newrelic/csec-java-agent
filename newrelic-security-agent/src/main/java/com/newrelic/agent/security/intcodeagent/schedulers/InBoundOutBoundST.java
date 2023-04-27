package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.constants.AgentServices;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpConnectionStat;
import com.newrelic.agent.security.intcodeagent.models.javaagent.OutBoundHttp;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;

import java.util.*;
import java.util.concurrent.*;

public class InBoundOutBoundST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String PRESENT_IN_CACHE_HTTP_CONNECTION = "present in cache http connection ";
    public static final String ADDING_HTTP_CONNECTION = "Adding http connection ";
    public static final String CONNECTION_LIST_FOR_POSTING = "Connection List for posting ";

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
            logger.log(LogLevel.FINER, PRESENT_IN_CACHE_HTTP_CONNECTION + outBoundHttp, InBoundOutBoundST.class.getName());
            OutBoundHttp cachedHttpCon = cache.get(outBoundHttp.getHashCode());
            cachedHttpCon.getCount().incrementAndGet();
            return false;
        } else {
            cache.put(outBoundHttp.getHashCode(), new OutBoundHttp(outBoundHttp));
            logger.log(LogLevel.FINER, ADDING_HTTP_CONNECTION + outBoundHttp, InBoundOutBoundST.class.getName());
            return newConnections.add(outBoundHttp);
        }
    }

    private InBoundOutBoundST() {
        logger.logInit(
                LogLevel.INFO,
                String.format(IAgentConstants.STARTING_MODULE_LOG, AgentServices.InBoundOutBoundMonitor.name()),
                InBoundOutBoundST.class.getName()
        );
        inOutExecutorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "NR-CSEC-inbound-outbound-st");
                t.setDaemon(true);
                return t;
            }
        });
        inOutExecutorService.scheduleAtFixedRate(runnable, 2, 2, TimeUnit.HOURS);
        cache = new ConcurrentHashMap<>();
        newConnections = ConcurrentHashMap.newKeySet();
        logger.logInit(
                LogLevel.INFO,
                String.format(IAgentConstants.STARTED_MODULE_LOG, AgentServices.InBoundOutBoundMonitor.name()),
                InBoundOutBoundST.class.getName()
        );
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
            task(cache.values(), true);
            cache.clear();
        }
    };

    public void task(Collection<OutBoundHttp> allConnections, boolean isCached) {
        /**
         * Create JSON
         * Send to IC
         * Clear cache
         * */
        logger.log(LogLevel.FINER, CONNECTION_LIST_FOR_POSTING + allConnections, InBoundOutBoundST.class.getName());
        List<OutBoundHttp> outBoundHttps = new ArrayList<>(allConnections);
        for (int i = 0; i < outBoundHttps.size(); i += 40) {
            int maxIndex = Math.min(i + 40, outBoundHttps.size());
            HttpConnectionStat httpConnectionStat = new HttpConnectionStat(outBoundHttps.subList(i, maxIndex), AgentInfo.getInstance().getApplicationUUID(), isCached);
            EventSendPool.getInstance().sendEvent(httpConnectionStat);
        }
    }

    public void clearNewConnections() {
        newConnections.clear();
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
    }

    /**
     * Shut down the thread pool executor. Calls normal shutdown of thread pool
     * executor and awaits for termination. If not terminated, forcefully shuts down
     * the executor after a timeout.
     */
    public void shutDownThreadPoolExecutor() {

        if (inOutExecutorService != null) {
            try {
                inOutExecutorService.shutdown(); // disable new tasks from being submitted
                if (!inOutExecutorService.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    inOutExecutorService.shutdownNow(); // cancel currently executing tasks

                    if (!inOutExecutorService.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                InBoundOutBoundST.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                InBoundOutBoundST.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}
