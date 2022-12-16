package com.newrelic.agent.security.introspec;

import com.newrelic.agent.security.introspec.schema.Operation;

import java.util.Iterator;

public interface SecurityIntrospector {

    Iterator<Operation> getOperations();

    void addOperation(Operation operation);

    void clear();
}
