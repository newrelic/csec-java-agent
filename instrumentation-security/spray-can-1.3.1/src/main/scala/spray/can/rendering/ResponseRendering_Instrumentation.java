package spray.can.rendering;

import akka.event.LoggingAdapter;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import spray.can.SprayHttpUtils;
import spray.http.HttpEntity;
import spray.http.HttpResponse;
import spray.http.Rendering;

import java.nio.charset.StandardCharsets;

@Weave(originalName = "spray.can.rendering.ResponseRenderingComponent$class")
public class ResponseRendering_Instrumentation {
    private static boolean renderResponse$1(ResponseRenderingComponent component, HttpResponse response,
            Rendering rendering, ResponsePartRenderingContext context, LoggingAdapter adapter) {

        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(SprayHttpUtils.getNrSecCustomAttribNameForResponse());
        try {
            if (isLockAcquired && response.entity().nonEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(new StringBuilder(response.entity().data().asString(StandardCharsets.UTF_8)));
                if (response.entity() instanceof HttpEntity.NonEmpty) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(((HttpEntity.NonEmpty) response.entity()).contentType().value());
                }
                SprayHttpUtils.postProcessSecurityHook(response, ResponseRendering_Instrumentation.class.getName(), "renderResponse$1");
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        boolean result;
        try {
            result = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                GenericHelper.releaseLock(SprayHttpUtils.getNrSecCustomAttribNameForResponse());
            }
        }
        return result;
    }

}
