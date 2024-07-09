package org.mule.module.http.internal.domain;

import com.newrelic.agent.security.instrumentation.mule36.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.InputStream;
import java.util.Objects;

@Weave(originalName = "org.mule.module.http.internal.domain.InputStreamHttpEntity")
public class InputStreamHttpEntity_Instrumentation {

    public InputStream getInputStream() {
        InputStream stream = Weaver.callOriginal();
        try {
            extractResponseBody(stream);
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_36, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_36, e.getMessage()), e, this.getClass().getName());
        }
        return stream;
    }

    private void extractResponseBody(InputStream stream) {
        if (NewRelicSecurity.isHookProcessingActive() && stream != null) {
            // check if it is an input or output stream
            if (Objects.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.RESPONSE_ENTITY_STREAM), Integer.class), this.hashCode())) {
                MuleHelper.registerOutputStreamHashIfNeeded(stream.hashCode());
            } else if (Objects.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.REQUEST_ENTITY_STREAM), Integer.class), this.hashCode())) {
                MuleHelper.registerInputStreamHashIfNeeded(stream.hashCode());
            }
        }
    }
}
