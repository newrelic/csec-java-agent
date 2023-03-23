package nr.java.net.http;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import nr.security.java.net.http.helper.SecurityHelper;

import java.net.http.HttpRequest;


@Weave(originalName = "java.net.http.HttpRequest", type = MatchType.BaseClass)
public abstract class HttpRequest_Instrumentation {

    @Weave(originalName = "java.net.http.HttpRequest$Builder", type = MatchType.Interface)
    public static class HttpRequestBuilder_Instrumentation {
        public HttpRequest build() {
            HttpRequest req =  Weaver.callOriginal();
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME + req.hashCode(), this);
            return req;
        }
    }
}
