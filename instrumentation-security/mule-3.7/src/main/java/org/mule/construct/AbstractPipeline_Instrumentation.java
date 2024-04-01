package org.mule.construct;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.api.processor.MessageProcessor;
import org.mule.api.source.MessageSource;
import org.mule.module.http.api.listener.HttpListener;

import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "org.mule.construct.AbstractPipeline")
public abstract class AbstractPipeline_Instrumentation {

    public abstract List<MessageProcessor> getMessageProcessors();
    public abstract MessageSource getMessageSource();
    protected void doInitialise(){
        try {
            Weaver.callOriginal();
        } finally {
            if (getMessageSource() instanceof HttpListener){
                MuleHelper.gatherURLMappings((HttpListener) getMessageSource(), getMessageProcessors());
            }
        }
    }
}
