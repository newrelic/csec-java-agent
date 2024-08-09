package graphql;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

@Weave(originalName = "graphql.ParseAndValidate", type = MatchType.ExactClass)
public class ParseAndValidate_Instrumentation {

}
