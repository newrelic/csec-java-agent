package jakarta.servlet.http;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.ServletException;

import java.io.IOException;

@Weave(type = MatchType.BaseClass, originalName = "jakarta.servlet.http.HttpServlet")
public class HttpServlet_Instrumentation {
    @NewField
    private String LIBRARY_NAME = "httpservlet";

    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }

    protected void doHead(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }

    protected void service(HttpServletRequest req, HttpServletResponse resp) {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }
}
