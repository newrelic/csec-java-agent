package org.springframework.web.servlet.mvc.condition;

import com.newrelic.api.agent.weaver.SkipIfPresent;

@SkipIfPresent(originalName = "org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition")
public class PathPatternsRequestCondition_Instrumentation {
}
