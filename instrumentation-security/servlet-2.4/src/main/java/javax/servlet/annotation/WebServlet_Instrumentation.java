package javax.servlet.annotation;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.WeaveIntoAllMethods;
import com.newrelic.api.agent.weaver.WeaveWithAnnotation;

@WeaveWithAnnotation(annotationClasses = {"javax.servlet.annotation.WebServlet"},
        type = MatchType.ExactClass)
public class WebServlet_Instrumentation {
    @WeaveIntoAllMethods
    private static void preprocessSecurityHook() {
        ServletHelper.registerUserLevelCode("servlet-annotation");
    }

}
