package akka.http.scaladsl.server.directives;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.util.Arrays;

public class AkkaHttpUtils {
    public static void processUserLevelServiceTrace() {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            StackTraceElement[] trace = securityMetaData.getMetaData().getServiceTrace();
            int trimFrameCount = 0;
            for (int i = 1; i < trace.length; i++) {
                if(StringUtils.startsWithAny(trace[i].getClassName(), "akka.http.scaladsl", "akka.http.javadsl")) {
                    trimFrameCount++;
                } else {
                    break;
                }
            }
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, trimFrameCount, trace.length));
          } catch (Throwable ignored) {
        }
    }

}
