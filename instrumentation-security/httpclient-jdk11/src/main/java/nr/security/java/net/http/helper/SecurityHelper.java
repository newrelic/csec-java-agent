package nr.security.java.net.http.helper;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;

import java.net.http.HttpRequest;

public class SecurityHelper {

    public static final String METHOD_NAME_SEND = "sendAsync";
    public static final String NULL_STRING = "null";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "HTTPCLIENT_JDK11_REQ_BUILDER_";

    public static HttpRequest addSecurityHeader(AbstractOperation operation, HttpRequest req) {
        HttpRequest updatedRequest = null;
        try {
            HttpRequest.Builder builder = NewRelicSecurity.getAgent()
                    .getSecurityMetaData()
                    .getCustomAttribute(SecurityHelper.NR_SEC_CUSTOM_ATTRIB_NAME + req.hashCode(), HttpRequest.Builder.class);
            String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
            if (iastHeader != null && !iastHeader.trim().isEmpty()) {
                builder.setHeader(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
            }
            if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() && operation.getExecutionId() != null &&
                    !operation.getExecutionId().trim().isEmpty()) {
                updatedRequest = builder.setHeader(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                        SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData().getTracingHeaderValue(), operation.getApiID(),
                                operation.getExecutionId(), NewRelicSecurity.getAgent().getAgentUUID())).build();
                return updatedRequest;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return req.newBuilder(req.uri()).build();
    }
}
