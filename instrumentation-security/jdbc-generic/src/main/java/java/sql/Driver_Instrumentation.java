package java.sql;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.Properties;

@Weave(originalName = "java.sql.Driver", type = MatchType.Interface)
public class Driver_Instrumentation {

    public Connection connect(String url, Properties info) throws SQLException {
        Connection connection = Weaver.callOriginal();
        if (connection != null && connection.getMetaData() != null) {
            NewRelicSecurity.getAgent().recordExternalConnection(null, -1, connection.getMetaData().getURL(), null, ExternalConnectionType.DATABASE_CONNECTION.name(), JdbcHelper.JDBC_GENERIC);
        }
        return connection;
    }
}
