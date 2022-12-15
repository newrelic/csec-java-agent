package com.newrelic.agent.security.introspec;

import com.newrelic.agent.security.introspec.schema.Operation;

import java.util.Set;

public interface SecurityIntrospector {

    Operation getOperation();

    void clear();
}
