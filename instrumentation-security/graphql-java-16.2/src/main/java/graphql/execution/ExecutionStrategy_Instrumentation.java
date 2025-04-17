package graphql.execution;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpRequestCustomDataTypeEnum;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import graphql.ExecutionInput;
import graphql.ExecutionResult;

import java.util.concurrent.CompletableFuture;

@Weave(type = MatchType.BaseClass, originalName = "graphql.execution.ExecutionStrategy")
public class ExecutionStrategy_Instrumentation {

    public CompletableFuture<ExecutionResult> execute(ExecutionContext executionContext, ExecutionStrategyParameters parameters) throws NonNullableFieldWasNullException {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                HttpRequest request = NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
                ExecutionInput executionInput = executionContext.getExecutionInput();
                if (executionInput.getQuery() != null && !executionInput.getQuery().isEmpty()) {
                    request.getCustomDataType().put("*.query", HttpRequestCustomDataTypeEnum.GRAPHQL_QUERY.name());
                }
                if (executionInput.getVariables() != null && !executionInput.getVariables().isEmpty()) {
                    request.getCustomDataType().put("*.variables", HttpRequestCustomDataTypeEnum.GRAPHQL_VARIABLE.name());
                }
            }
        } catch (Exception ignored) {}
        return Weaver.callOriginal();
    }
}
