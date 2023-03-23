package io.r2dbc.spi;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "io.r2dbc.spi.Connection")
public class Connection_Instrumentation {

    public Statement_Instrumention createStatement(String sql) {
        Statement_Instrumention statement = Weaver.callOriginal();
        statement.sql = sql;
        return statement;
    }
}
