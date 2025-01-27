package org.mule.module.http.internal.domain;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.InputStream;

@Weave(originalName = "org.mule.module.http.internal.domain.InputStreamHttpEntity")
public class InputStreamHttpEntity_Instrumentation {

    public InputStream getInputStream() {
        InputStream stream = Weaver.callOriginal();
        try {
            extractResponseBody(stream);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_37, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_37, e.getMessage()), e, this.getClass().getName());
        }
        return stream;
    }

    private void extractResponseBody(InputStream stream) {
        if (NewRelicSecurity.isHookProcessingActive() && stream != null) {
            // check if it is an input or output stream
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            // outputBody stream
            if (MuleHelper.preprocessStream(this.hashCode(), MuleHelper.RESPONSE_ENTITY_STREAM)) {
                MuleHelper.registerStreamHashIfNeeded(stream.hashCode(), MuleHelper.RESPONSE_OUTPUTSTREAM_HASH);
            }
            // inputBody stream
            else if (MuleHelper.preprocessStream(this.hashCode(), MuleHelper.REQUEST_ENTITY_STREAM)) {
                MuleHelper.registerStreamHashIfNeeded(stream.hashCode(), MuleHelper.REQUEST_INPUTSTREAM_HASH);
            }
        }
    }

}