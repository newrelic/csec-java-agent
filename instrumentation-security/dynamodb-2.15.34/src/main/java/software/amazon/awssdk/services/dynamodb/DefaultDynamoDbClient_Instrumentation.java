package software.amazon.awssdk.services.dynamodb;

import com.newrelic.agent.security.instrumentation.dynamodb_215.DynamoDBUtil;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import software.amazon.awssdk.core.client.config.SdkClientConfiguration;
import software.amazon.awssdk.core.client.config.SdkClientOption;

import java.net.URI;

@Weave(originalName = "software.amazon.awssdk.services.dynamodb.DefaultDynamoDbClient", type = MatchType.ExactClass)
final class DefaultDynamoDbClient_Instrumentation {

    protected DefaultDynamoDbClient_Instrumentation(SdkClientConfiguration clientConfiguration) {
        try {
            URI endpoint = clientConfiguration != null ? clientConfiguration.option(SdkClientOption.ENDPOINT) : null;
            if (endpoint != null) {
                NewRelicSecurity.getAgent().recordExternalConnection(endpoint.getHost(), endpoint.getPort(), null, null,
                        ExternalConnectionType.DATABASE_CONNECTION.name(), DynamoDBUtil.DYNAMODB_2_15_34);
            }
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, DynamoDBUtil.DYNAMODB_2_15_34, e.getMessage()), this.getClass().getName());
        }
    }
}
