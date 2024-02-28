package com.newrelic.agent.security.instrumentation.http;

import com.newrelic.agent.security.instrumentation.helper.SecurityHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.net.http.HttpRequest;


@Weave(originalName = "java.net.http.HttpRequest", type = MatchType.BaseClass)
public abstract class HttpRequest_Instrumentation {

    @Weave(originalName = "java.net.http.HttpRequest$Builder", type = MatchType.Interface)
    public static class HttpRequestBuilder_Instrumentation {
        public HttpRequest build() {
            HttpRequest req = null;
            try {
                req =  Weaver.callOriginal();
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME + req.hashCode(), this);
            } catch (Exception e){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, SecurityHelper.HTTPCLIENT_JDK_11, e.getMessage()), e, this.getClass().getName());
            }
            return req;
        }
    }
}
