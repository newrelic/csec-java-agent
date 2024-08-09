package graphql;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpRequestCustomDataTypeEnum;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import graphql.execution.instrumentation.InstrumentationState;
import graphql.language.Document;
import graphql.schema.GraphQLSchema;

import java.util.concurrent.CompletableFuture;

@Weave(originalName = "graphql.GraphQL", type = MatchType.ExactClass)
public class GraphQL_Instrumentation {

    private CompletableFuture<ExecutionResult> execute(ExecutionInput executionInput, Document document, GraphQLSchema graphQLSchema, InstrumentationState instrumentationState) {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                HttpRequest request = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
                if (executionInput.getQuery() != null && !executionInput.getQuery().isEmpty()) {
                    request.getCustomDataType().put("*.query", HttpRequestCustomDataTypeEnum.GRAPHQL_QUERY.name());
                }
                if (executionInput.getQuery() != null && !executionInput.getVariables().isEmpty()) {
                    request.getCustomDataType().put("*.variables", HttpRequestCustomDataTypeEnum.GRAPHQL_VARIABLE.name());
                }
            }
        } catch (Exception ignored) {}
        return Weaver.callOriginal();
    }
}
