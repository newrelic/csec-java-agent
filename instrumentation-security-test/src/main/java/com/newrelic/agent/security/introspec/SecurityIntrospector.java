package com.newrelic.agent.security.introspec;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.api.agent.security.schema.AbstractOperation;

import java.util.Iterator;

public interface SecurityIntrospector {

    Iterator<AbstractOperation> getOperations();

    void addExitEvent(AbstractOperation operation);

    Iterator<ExitEventBean> getExitEvents();

    void addExitEvent(ExitEventBean exitEvent);


    void clear();
}
