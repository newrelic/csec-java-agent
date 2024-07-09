package org.mule.module.http.internal.domain;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.apache.commons.io.Charsets;
import org.mule.util.IOUtils;

import java.io.IOException;
import java.util.Objects;

@Weave(originalName = "org.mule.module.http.internal.domain.ByteArrayHttpEntity")
public class ByteArrayHttpEntity_Instrumentation {

    public byte[] getContent() {
        byte[] content = Weaver.callOriginal();
        try {
            extractResponseBody(content);
        } catch (IOException e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_37, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE_BODY, MuleHelper.MULE_37, e.getMessage()), e, this.getClass().getName());
        }
        return content;
    }

    private void extractResponseBody(byte[] content) throws IOException {
        if (NewRelicSecurity.isHookProcessingActive()){
            String encoding = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(MuleHelper.MULE_ENCODING, String.class);
            if (encoding == null || encoding.isEmpty()){
                encoding = Charsets.UTF_8.name();
            }
            String body = IOUtils.toString(content, encoding);
            
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (Objects.equals(securityMetaData.getCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.RESPONSE_ENTITY_STREAM), Integer.class), this.hashCode())) {
                securityMetaData.getResponse().getResponseBody().append(body);
            } else if (Objects.equals(securityMetaData.getCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.REQUEST_ENTITY_STREAM), Integer.class), this.hashCode())) {
                securityMetaData.getRequest().getBody().append(body);
            }
        }
    }
}
