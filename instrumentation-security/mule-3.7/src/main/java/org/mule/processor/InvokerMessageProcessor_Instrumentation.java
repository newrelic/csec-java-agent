package org.mule.processor;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.api.MuleEvent;
import org.mule.api.MuleException;
import org.mule.api.lifecycle.InitialisationException;

@Weave(originalName = "org.mule.processor.InvokerMessageProcessor", type = MatchType.ExactClass)
public class InvokerMessageProcessor_Instrumentation {
    protected Object object = Weaver.callOriginal();

    public void initialise() throws InitialisationException {
        try {
            Weaver.callOriginal();
        } finally {
            MuleHelper.getHandlerMap().put(hashCode(), object.getClass().getName());
            URLMappingsHelper.getHandlersHash().add(object.getClass().getName().hashCode());
        }
    }

    public MuleEvent process(MuleEvent event) throws MuleException {
        ServletHelper.registerUserLevelCode(MuleHelper.LIBRARY_NAME);
        return Weaver.callOriginal();
    }
}
