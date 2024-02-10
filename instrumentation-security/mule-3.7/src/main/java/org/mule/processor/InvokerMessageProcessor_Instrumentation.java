package org.mule.processor;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.api.lifecycle.InitialisationException;

@Weave(originalName = "org.mule.processor.InvokerMessageProcessor", type = MatchType.ExactClass)
public class InvokerMessageProcessor_Instrumentation {
    protected Object object = Weaver.callOriginal();

    public void initialise() throws InitialisationException {
        try {
            Weaver.callOriginal();
        } finally {
            MuleHelper.getHandlerMap().put(hashCode(), object.getClass().getName());
        }
    }
}
