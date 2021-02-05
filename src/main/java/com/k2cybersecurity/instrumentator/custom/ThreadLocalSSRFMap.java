package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.OutBoundHttp;

import java.util.HashSet;
import java.util.Set;

public class ThreadLocalSSRFMap {

    private Set<OutBoundHttp> alreadyEncounteredRecords;

    private static ThreadLocal<ThreadLocalSSRFMap> instance =
            new ThreadLocal<ThreadLocalSSRFMap>() {
                @Override
                protected ThreadLocalSSRFMap initialValue() {
                    return new ThreadLocalSSRFMap();
                }
            };

    private ThreadLocalSSRFMap() {
        this.alreadyEncounteredRecords = new HashSet<>();
    }

    public static ThreadLocalSSRFMap getInstance() {
        return instance.get();
    }

    public boolean isAlreadyEncountered(OutBoundHttp outBoundHttp) {
        return alreadyEncounteredRecords.contains(outBoundHttp);
    }

    public void addToAlreadyEncountered(OutBoundHttp outBoundHttp) {
        this.alreadyEncounteredRecords.add(outBoundHttp);
    }

    public void cleanUp() {
        this.alreadyEncounteredRecords.clear();
    }

}
