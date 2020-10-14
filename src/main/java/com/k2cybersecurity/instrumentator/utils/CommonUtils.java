package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.models.javaagent.Identifier;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

public class CommonUtils {


    public static Pair<String, String> getKindIdPair(Identifier identifier, String hostId) {
        if(identifier.getIsContainer()){
            return new ImmutablePair<>("CONTAINER", identifier.getContainerId());
        } else if(identifier.getIsECSContainer()){
            return new ImmutablePair<>("ECS", identifier.getEcsTaskId());
        } else if(identifier.getIsPod()){
            return new ImmutablePair<>("CONTAINER", identifier.getPodId());
        } else {
            return new ImmutablePair<>("HOST", hostId);
        }
    }
}
