package com.k2cybersecurity.intcodeagent.logging;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

public interface IAgentConstants {

	public static final String CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT = "weblogic/servlet/internal/WebAppServletContext";

	String TRACE_REGEX = "(?!(org\\.apache\\.jsp.*))((^javax.*)|(^org\\.apache.*)|(^sun.*)|(^java.*)|(^k2\\.org\\.brutusin.*)|(^com\\.k2cybersecurity\\.intcodeagent.*)|(^k2\\.io\\.org.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^org\\.hibernate.*)|(^com\\.mongodb.*)|(^org\\.apache\\.commons.*)|(^org\\.mongodb.*)|(^com\\.sun.*)|(^org\\.eclipse\\.jetty.*)|(^net\\.sourceforge\\.eclipsejetty.*)|(^org\\.springframework.*)|(^org\\.slf4j.*)|(^org\\.eclipse\\.jdt.*)|(^com\\.opensymphony\\.xwork2.*)|(^k2\\.org\\.objectweb\\.asm.*)|(^freemarker\\.cache.*)|(^com\\.mchange.*)|(^org\\.postgresql.*)|(^oracle\\.jdbc.*)|(^org\\.hsqldb.*)|(^ch\\.qos\\.logback.*)|(^io\\.micrometer.*)|(^k2\\.org\\.json.*)|(^k2\\.com\\.fasterxml.*)|(^jdk\\..*))|(^com\\.ibm\\.ws.*)";

	// HSQL
	String CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION = "org/hsqldb/HSQLClientConnection";
	String CLASS_ORG_HSQLDB_SESSION = "org/hsqldb/Session";

	// PSQL
	String CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL = "org/postgresql/core/v2/QueryExecutorImpl";
	String CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL = "org/postgresql/core/v3/QueryExecutorImpl";

	// JETTY
	String CLASS_ORG_ECLIPSE_JETTY_HTTP_HTTP_PARSER = "org/eclipse/jetty/http/HttpParser";
	String CLASS_ORG_ECLIPSE_JETTY_SERVER_HTTP_CONNECTION = "org/eclipse/jetty/server/HttpConnection";

	// APACHE TOMCAT
	String CLASS_ORG_APACHE_CATALINA_CONNECTOR_INPUT_BUFFER = "org/apache/catalina/connector/InputBuffer";
	String CLASS_ORG_APACHE_CATALINA_CONNECTOR_COYOTE_ADAPTER = "org/apache/catalina/connector/CoyoteAdapter";

	// ORACLE
	String CLASS_ORACLE_JDBC_DRIVER_T4CTT_IFUN = "oracle/jdbc/driver/T4CTTIfun";
	
	// Oracle Weblogic
	String CLASS_WEBLOGIC_SERVLET_INTERNAL_STUBSECURITYHELPER = "weblogic/servlet/internal/StubSecurityHelper";

	// CLASSLOADER
	String CLASS_JAVA_NET_URL_CLASS_LOADER = "java/net/URLClassLoader";

	// MONGO
	String CLASS_COM_MONGODB_ASYNC_CLIENT_OPERATION_EXECUTOR_IMPL = "com/mongodb/async/client/OperationExecutorImpl";
	String CLASS_COM_MONGODB_ASYNC_CLIENT_ASYNC_OPERATION_EXECUTOR_IMPL = "com/mongodb/async/client/AsyncOperationExecutorImpl";
	String CLASS_COM_MONGODB_ASYNC_CLIENT_MONGO_CLIENT_IMPL$2 = "com/mongodb/async/client/MongoClientImpl$2";
	String CLASS_COM_MONGODB_INTERNAL_CONNECTION_DEFAULT_SERVER_CONNECTION = "com/mongodb/internal/connection/DefaultServerConnection";
	String CLASS_COM_MONGODB_CONNECTION_DEFAULT_SERVER_CONNECTION = "com/mongodb/connection/DefaultServerConnection";

	// MYSQL
	String CLASS_COM_MYSQL_JDBC_SERVER_PREPARED_STATEMENT = "com/mysql/jdbc/ServerPreparedStatement";
	String CLASS_COM_MYSQL_CJ_NATIVE_SESSION = "com/mysql/cj/NativeSession";
	String CLASS_COM_MYSQL_CJ_MYSQLA_IO_MYSQLA_PROTOCOL = "com/mysql/cj/mysqla/io/MysqlaProtocol";
	String CLASS_COM_MYSQL_JDBC_MYSQL_IO = "com/mysql/jdbc/MysqlIO";

	// MSSQL
	String CLASS_COM_MICROSOFT_SQLSERVER_JDBC_SQL_SERVER_STATEMENT = "com/microsoft/sqlserver/jdbc/SQLServerStatement";

	// FORKEXEC
	String CLASS_JAVA_LANG_PROCESS_IMPL = "java/lang/ProcessImpl";

	//WSLiberty
	String COM_IBM_WS_GENERICBNF_INTERNAL_BNFHEADERSIMPL = "com/ibm/ws/genericbnf/internal/BNFHeadersImpl";
	String COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTPINBOUNDLINK = "com/ibm/ws/http/channel/internal/inbound/HttpInboundLink";

	//WAS Traditional
	String COM_IBM_WS_GENERICBNF_IMPL_BNFHEADERSIMPL = "com/ibm/ws/genericbnf/impl/BNFHeadersImpl";
	String COM_IBM_WS_HTTP_CHANNEL_INBOUND_IMPL_HTTPINBOUNDLINK = "com/ibm/ws/http/channel/inbound/impl/HttpInboundLink";
	
	
	String EXEC_URL_CLASS_LOADER_NEW_INSTANCE = "public static java.net.URLClassLoader java.net.URLClassLoader.newInstance(java.net.URL[])";

	String EXEC_DEFINE_CLASS = "private java.lang.Class<?> java.net.URLClassLoader.defineClass(java.lang.String,sun.misc.Resource) throws java.io.IOException";

	String URL_CLASS_LOADER = "public java.net.URLClassLoader(java.net.URL[])";

	String EXEC_ORACLE = // oracle db
			"final void oracle.jdbc.driver.T4CTTIfun.doRPC() throws java.io.IOException,java.sql.SQLException";

	String EXEC_MYSQL_8X = // Mysql Connector/J 8.x
			"public <T> T com.mysql.cj.NativeSession.execSQL(com.mysql.cj.Query,java.lang.String,int,com.mysql.cj.protocol.a.NativePacketPayload,boolean,com.mysql.cj.protocol.ProtocolEntityFactory<T, com.mysql.cj.protocol.a.NativePacketPayload>,java.lang.String,com.mysql.cj.protocol.ColumnDefinition,boolean)";

	String EXEC_MYSQL_6X4 = "private com.mysql.jdbc.ResultSet com.mysql.jdbc.ServerPreparedStatement.serverExecute(int,boolean) throws java.sql.SQLException";

	String EXEC_MYSQL_6X3 = "public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,boolean,java.lang.String,com.mysql.cj.api.mysqla.result.ColumnDefinition,com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction,com.mysql.cj.api.mysqla.io.ProtocolEntityFactory<T>) throws java.io.IOException";

	String EXEC_MYSQL_6X2 = "public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[],com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction)";

	String EXEC_MYSQL_6X = // Mysql Connector/J 6.x
			"public final com.mysql.cj.api.jdbc.ResultSetInternalMethods com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.mysqla.io.Buffer,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[])";

	String EXEC_MYSQL_51X = // Mysql Connector/J 5.1.x
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception";

	String EXEC_MYSQL_505 = // mysql calls
			// Mysql Connector/J 5.0.5
			"final com.mysql.jdbc.ResultSet com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.Statement,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,com.mysql.jdbc.Connection,int,int,boolean,java.lang.String,boolean) throws java.lang.Exception";

	String EXEC_MSSQL = "final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String EXEC_MSSQL_SQLTIMEOUT = // mssql calls
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException,java.sql.SQLTimeoutException";

	String SYSYTEM_CALL_START = "static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException";

	// http client
	String CLASS_HTTP_REQUEST_EXECUTOR = "org/apache/http/protocol/HttpRequestExecutor";

	String APACHE_HTTP_REQUEST_EXECUTOR_METHOD = "protected org.apache.http.HttpResponse org.apache.http.protocol.HttpRequestExecutor.doSendRequest(org.apache.http.HttpRequest,org.apache.http.HttpClientConnection,org.apache.http.protocol.HttpContext) throws java.io.IOException,org.apache.http.HttpException";
	
	String CLASS_JAVA_HTTP_HANDLER = "sun/net/www/protocol/http/Handler";
	String CLASS_JAVA_HTTPS_HANDLER = "sun/net/www/protocol/https/Handler";
	String CLASS_JAVA_SSL_HTTPS_HANDLER = "com/sun/net/ssl/internal/www/protocol/https/Handler";
	
	String JAVA_OPEN_CONNECTION_METHOD2 = "protected java.net.URLConnection sun.net.www.protocol.http.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";
	String JAVA_OPEN_CONNECTION_METHOD2_HTTPS = "protected java.net.URLConnection sun.net.www.protocol.https.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";
	String JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2 = "protected java.net.URLConnection com.sun.net.ssl.internal.www.protocol.https.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";
	
	String CLASS_JDK_INCUBATOR_HTTP_MULTIEXCHANGE = "jdk/incubator/http/MultiExchange";
	String JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD = "public jdk.incubator.http.HttpResponseImpl<T> jdk.incubator.http.MultiExchange.response() throws java.io.IOException,java.lang.InterruptedException";
	String JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD = "public java.util.concurrent.CompletableFuture<jdk.incubator.http.HttpResponseImpl<T>> jdk.incubator.http.MultiExchange.responseAsync()";
	
	String CLASS_APACHE_COMMONS_HTTP_METHOD_DIRECTOR = "org/apache/commons/httpclient/HttpMethodDirector";
	String APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD = "private void org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(org.apache.commons.httpclient.HttpMethod) throws java.io.IOException,org.apache.commons.httpclient.HttpException";
	
	String CLASS_OKHTTP_HTTP_ENGINE = "com/squareup/okhttp/internal/http/HttpEngine";
	String OKHTTP_HTTP_ENGINE_METHOD = "public void com.squareup.okhttp.internal.http.HttpEngine.sendRequest() throws com.squareup.okhttp.internal.http.RequestException,com.squareup.okhttp.internal.http.RouteException,java.io.IOException";

	String CLASS_WEBLOGIC_HTTP_HANDLER = "weblogic/net/http/Handler";
	String WEBLOGIC_OPEN_CONNECTION_METHOD = "protected java.net.URLConnection weblogic.net.http.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";

	List<String> FILE_OPEN_EXECUTORS = Arrays.asList(new String[] {
			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" });

	Map<String, List<String>> MYSQL_GET_CONNECTION_MAP = new HashMap<String, List<String>>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = 3518358544335663220L;
		{
			put("java.sql.DriverManager", Collections.singletonList("getConnection"));
			put("com.mysql.jdbc.ConnectionImpl", Arrays.asList("getInstance", "isReadOnly"));
		}
	};

	Map<String, VulnerabilityCaseType> MONGO_EXECUTORS = new HashMap<String, VulnerabilityCaseType>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = -7680282029242613768L;

		{
			// asynchronous mongo calls
			put("public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			// synchronous mongo calls
			put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
					VulnerabilityCaseType.DB_COMMAND);
			put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.LegacyProtocol<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
					VulnerabilityCaseType.DB_COMMAND);
			put("private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.LegacyProtocol<T>)",
					VulnerabilityCaseType.DB_COMMAND);
			put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.Protocol<T>)",
					VulnerabilityCaseType.DB_COMMAND);
		}
	};

	String SERVLET_REQUEST_FACADE = "public org.apache.catalina.connector.RequestFacade(org.apache.catalina.connector.Request)";

	String PSQLV3_EXECUTOR = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.v3.V3Query,org.postgresql.core.v3.V3ParameterList,int,int,int,org.postgresql.core.v3.QueryExecutorImpl$ErrorTrackingResultHandler) throws java.io.IOException,java.sql.SQLException";

	String PSQLV2_EXECUTOR = "protected void org.postgresql.core.v2.QueryExecutorImpl.sendQuery(org.postgresql.core.v2.V2Query,org.postgresql.core.v2.SimpleParameterList,java.lang.String) throws java.io.IOException";

	String PSQL42_EXECUTOR = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.Query,org.postgresql.core.v3.V3ParameterList,int,int,int,org.postgresql.core.ResultHandler,org.postgresql.jdbc.BatchResultHandler) throws java.io.IOException,java.sql.SQLException";

	// Postgres V3 API : > Server 7.4 < Server 9.X
	String PSQLV3_EXECUTOR7_4 = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.v3.V3Query,org.postgresql.core.v3.V3ParameterList,int,int,int) throws java.io.IOException,java.sql.SQLException";

	// HSQL_DB v2.4
	String HSQL_V2_4 = "public org.hsqldb.result.Result org.hsqldb.Session.executeCompiledStatement(org.hsqldb.Statement,java.lang.Object[],int)";

	// HSQL_DB v1.8
	String HSQL_V1_8_CONNECTION = "public synchronized org.hsqldb.Result org.hsqldb.HSQLClientConnection.execute(org.hsqldb.Result) throws org.hsqldb.HsqlException";

	String HSQL_V1_8_SESSION = "public org.hsqldb.Result org.hsqldb.Session.execute(org.hsqldb.Result)";

	// MSSQL

	Map<String, VulnerabilityCaseType> EXECUTORS = new HashMap<String, VulnerabilityCaseType>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = -6864398309462801187L;

		{
			// System Command
			put(SYSYTEM_CALL_START, VulnerabilityCaseType.SYSTEM_COMMAND);
			
			// MSSQL
			put(EXEC_MSSQL_SQLTIMEOUT, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MSSQL, VulnerabilityCaseType.DB_COMMAND);

			// MYSQL
			put(EXEC_MYSQL_505, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_51X, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_6X, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_6X2, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_6X3, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_6X4, VulnerabilityCaseType.DB_COMMAND);
			put(EXEC_MYSQL_8X, VulnerabilityCaseType.DB_COMMAND);

			// ORACLE
			put(EXEC_ORACLE, VulnerabilityCaseType.DB_COMMAND);

			// postgresql
			put(PSQLV3_EXECUTOR, VulnerabilityCaseType.DB_COMMAND);
			put(PSQLV2_EXECUTOR, VulnerabilityCaseType.DB_COMMAND);
			put(PSQL42_EXECUTOR, VulnerabilityCaseType.DB_COMMAND);
			put(PSQLV3_EXECUTOR7_4, VulnerabilityCaseType.DB_COMMAND);

			// HSQLDB
			put(HSQL_V2_4, VulnerabilityCaseType.DB_COMMAND);
			put(HSQL_V1_8_CONNECTION, VulnerabilityCaseType.DB_COMMAND);
			put(HSQL_V1_8_SESSION, VulnerabilityCaseType.DB_COMMAND);

			// MongoDB
			putAll(MONGO_EXECUTORS);
			
			// dynamic class loading
			put(URL_CLASS_LOADER, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);
			put(EXEC_DEFINE_CLASS, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);
			put(EXEC_URL_CLASS_LOADER_NEW_INSTANCE, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);

			// // FileWriter
//			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
//			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)",

			// File Input
			// "public java.io.FileInputStream(java.lang.String) throws
			// java.io.FileNotFoundException",
			// "public java.io.FileInputStream(java.io.File) throws
			// java.io.FileNotFoundException",

			// http request
			put(APACHE_HTTP_REQUEST_EXECUTOR_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
			
			//JAVA_OPEN_CONNECTION_METHOD,
			put(JAVA_OPEN_CONNECTION_METHOD2, VulnerabilityCaseType.HTTP_REQUEST);
			put(JAVA_OPEN_CONNECTION_METHOD2_HTTPS, VulnerabilityCaseType.HTTP_REQUEST);
			put(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2, VulnerabilityCaseType.HTTP_REQUEST);
			put(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
			put(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
			put(APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
			put(OKHTTP_HTTP_ENGINE_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
			put(WEBLOGIC_OPEN_CONNECTION_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
		}
	};

	String HTTP_SERVLET_SERVICE = "protected void javax.servlet.http.HttpServlet.service(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws javax.servlet.ServletException,java.io.IOException";

	String STRUTS2_DO_FILTER = "public void org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter.doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain) throws java.io.IOException,javax.servlet.ServletException";

	String MSSQL_EXECUTOR = "boolean com.microsoft.sqlserver.jdbc.SQLServerConnection.executeCommand(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String[] CONSTRUCTOR = { "<init>" };

	Map<String, List<String>> INSTRUMENTED_METHODS = new HashMap<String, List<String>>() {
		private static final long serialVersionUID = -7680282029242613768L;

		{
			put(CLASS_JAVA_LANG_PROCESS_IMPL, Collections.singletonList("start"));
			put(CLASS_COM_MICROSOFT_SQLSERVER_JDBC_SQL_SERVER_STATEMENT, Collections.singletonList("executeStatement"));
			put(CLASS_COM_MYSQL_CJ_MYSQLA_IO_MYSQLA_PROTOCOL, Collections.singletonList("sqlQueryDirect"));
			put(CLASS_COM_MYSQL_JDBC_MYSQL_IO, Collections.singletonList("sqlQueryDirect"));
			put(CLASS_COM_MYSQL_CJ_NATIVE_SESSION, Collections.singletonList("execSQL"));
			put(CLASS_COM_MYSQL_JDBC_SERVER_PREPARED_STATEMENT, Collections.singletonList("serverExecute"));
			put(CLASS_COM_MONGODB_CONNECTION_DEFAULT_SERVER_CONNECTION, Collections.singletonList("executeProtocol"));
			put(CLASS_COM_MONGODB_INTERNAL_CONNECTION_DEFAULT_SERVER_CONNECTION,
					Collections.singletonList("executeProtocol"));
			put(CLASS_COM_MONGODB_ASYNC_CLIENT_MONGO_CLIENT_IMPL$2, Collections.singletonList("execute"));
			put(CLASS_COM_MONGODB_ASYNC_CLIENT_ASYNC_OPERATION_EXECUTOR_IMPL, Collections.singletonList("execute"));
			put(CLASS_COM_MONGODB_ASYNC_CLIENT_OPERATION_EXECUTOR_IMPL, Collections.singletonList("execute"));
			put(CLASS_JAVA_NET_URL_CLASS_LOADER, Arrays.asList(new String[] { "<init>", "newInstance" }));
			put(CLASS_ORACLE_JDBC_DRIVER_T4CTT_IFUN, Collections.singletonList("doRPC"));
			put(CLASS_ORG_APACHE_CATALINA_CONNECTOR_COYOTE_ADAPTER, Collections.singletonList("service"));
			put(CLASS_ORG_APACHE_CATALINA_CONNECTOR_INPUT_BUFFER, Collections.singletonList("setByteBuffer"));
			put(CLASS_ORG_ECLIPSE_JETTY_SERVER_HTTP_CONNECTION, Collections.singletonList("onFillable"));
			put(CLASS_ORG_ECLIPSE_JETTY_HTTP_HTTP_PARSER, Collections.singletonList("parseNext"));
			put(CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL, Collections.singletonList("sendQuery"));
			put(CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL, Collections.singletonList("sendQuery"));
			put(CLASS_ORG_HSQLDB_SESSION, Arrays.asList(new String[] { "executeCompiledStatement", "execute" }));
			put(CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION, Collections.singletonList("execute"));
			put(COM_IBM_WS_GENERICBNF_INTERNAL_BNFHEADERSIMPL, Collections.singletonList("fillByteCache"));
			put(COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTPINBOUNDLINK, Collections.singletonList("processRequest"));
			put(COM_IBM_WS_GENERICBNF_IMPL_BNFHEADERSIMPL, Collections.singletonList("fillByteCache"));
			put(COM_IBM_WS_HTTP_CHANNEL_INBOUND_IMPL_HTTPINBOUNDLINK, Collections.singletonList("processRequest"));
			
			put(CLASS_HTTP_REQUEST_EXECUTOR, Collections.singletonList("doSendRequest"));
			put(CLASS_JAVA_HTTP_HANDLER, Collections.singletonList("openConnection"));
			put(CLASS_JAVA_HTTPS_HANDLER, Collections.singletonList("openConnection"));
			put(CLASS_JAVA_SSL_HTTPS_HANDLER, Collections.singletonList("openConnection"));
			put(CLASS_JDK_INCUBATOR_HTTP_MULTIEXCHANGE, Arrays.asList(new String[] { "response", "responseAsync", "multiResponseAsync" }));
//			put(CLASS_WEBLOGIC_SERVLET_INTERNAL_STUBSECURITYHELPER, Collections.singletonList("invokeServlet"));
			put(CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT, Collections.singletonList("execute"));
			put(CLASS_APACHE_COMMONS_HTTP_METHOD_DIRECTOR, Collections.singletonList("executeWithRetry"));
			put(CLASS_OKHTTP_HTTP_ENGINE, Collections.singletonList("sendRequest"));
			put(CLASS_WEBLOGIC_HTTP_HANDLER, Collections.singletonList("openConnection"));
		}
	};

	/** Source Method Identifiers for argument resolution */
	String MSSQL_IDENTIFIER = "com.microsoft.sqlserver";
	String MYSQL_IDENTIFIER = "com.mysql";
	String MONGO_IDENTIFIER = "com.mongo";
	String CLASS_LOADER_IDENTIFIER = "java.net.URLClassLoader";
	String SERVLET_REQUEST_IDENTIFIER = "javax.servlet.http.HttpServletRequest";

	String TOMCAT_COYOTE_ADAPTER_SERVICE = "public void org.apache.catalina.connector.CoyoteAdapter.service(org.apache.coyote.Request,org.apache.coyote.Response) throws java.lang.Exception";
	String TOMCAT_SETBYTEBUFFER = "public void org.apache.catalina.connector.InputBuffer.setByteBuffer(java.nio.ByteBuffer)";

	String FACES_SERVLET = "public void javax.faces.webapp.FacesServlet.service(javax.servlet.ServletRequest,javax.servlet.ServletResponse) throws java.io.IOException,javax.servlet.ServletException";
	String JETTY_SERVLET_REQUEST_IDENTIFIER = "org.eclipse.jetty.server.Request";
	String JETTY_REQUEST_ON_FILLABLE = "public void org.eclipse.jetty.server.HttpConnection.onFillable()";
	String JETTY_PARSE_NEXT = "public boolean org.eclipse.jetty.http.HttpParser.parseNext(java.nio.ByteBuffer)";

	String WEBSPHERE_LIBERTY_FILLBYTECACHE = "protected boolean com.ibm.ws.genericbnf.internal.BNFHeadersImpl.fillByteCache(com.ibm.wsspi.bytebuffer.WsByteBuffer)";
	String WEBSPHERE_LIBERTY_PROCESSREQUEST = "protected void com.ibm.ws.http.channel.internal.inbound.HttpInboundLink.processRequest()";
	String WEBSPHERE_TRADITIONAL_FILLBYTECACHE = "protected boolean com.ibm.ws.genericbnf.impl.BNFHeadersImpl.fillByteCache(com.ibm.wsspi.buffermgmt.WsByteBuffer)";
	String WEBSPHERE_TRADITIONAL_PROCESSREQUEST = "protected void com.ibm.ws.http.channel.inbound.impl.HttpInboundLink.processRequest()";
	
	String WEBLOGIC_INVOKE_SERVLET = "public java.lang.Throwable weblogic.servlet.internal.StubSecurityHelper.invokeServlet(javax.servlet.ServletRequest,javax.servlet.http.HttpServletRequest,weblogic.servlet.internal.ServletRequestImpl,javax.servlet.ServletResponse,javax.servlet.http.HttpServletResponse,javax.servlet.Servlet) throws javax.servlet.ServletException";
	
	String WEBLOGIC_SERVLET_EXECUTE = "void weblogic.servlet.internal.WebAppServletContext.execute(weblogic.servlet.internal.ServletRequestImpl,weblogic.servlet.internal.ServletResponseImpl) throws java.io.IOException";
	
	/** MSSQL FIELD CONSTANTS */
	String MSSQL_CURRENT_OBJECT = "this$0";
	String MSSQL_BATCH_STATEMENT_BUFFER_FIELD = "batchStatementBuffer";
	String MSSQL_SQL_FIELD = "sql";
	String MSSQL_CONNECTION_FIELD = "connection";
	String MSSQL_ACTIVE_CONNECTION_PROP_FIELD = "activeConnectionProperties";
	String MSSQL_STATEMENT_FIELD = "stmt";
	String MSSQL_USER_SQL_FIELD = "userSQL";
	String MSSQL_IN_OUT_PARAM_FIELD = "inOutParam";
	String MSSQL_BATCH_PARAM_VALUES_FIELD = "batchParamValues";
	String MSSQL_INPUT_DTV_FIELD = "inputDTV";
	String MSSQL_IMPL_FIELD = "impl";
	String MSSQL_VALUE_FIELD = "value";

	/** MSSQL CLASS CONSTANTS */
	String MSSQL_SERVER_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement";
	String MSSQL_PREPARED_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement";
	String MSSQL_PREPARED_BATCH_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement.PrepStmtBatchExecCmd";
	String MSSQL_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtExecCmd";
	String MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtBatchExecCmd";

	/** MySQL CLASS CONSTANTS */
	String MYSQL_PREPARED_STATEMENT_4 = "com.mysql.jdbc.JDBC4PreparedStatement";
	String MYSQL_PREPARED_STATEMENT_42 = "com.mysql.jdbc.JDBC42PreparedStatement";
	String MYSQL_PREPARED_STATEMENT_5_0_4 = "com.mysql.jdbc.ServerPreparedStatement";
	String MYSQL_PREPARED_STATEMENT_5 = "com.mysql.jdbc.PreparedStatement";
	String MYSQL_PREPARED_STATEMENT_6 = "com.mysql.cj.jdbc.PreparedStatement";
	String MYSQL_PREPARED_STATEMENT_8 = "com.mysql.cj.jdbc.ClientPreparedStatement";
	String MYSQL_PREPARED_QUERY_8 = "com.mysql.cj.ClientPreparedQuery";
	String MYSQL_PREPARED_STATEMENT_SOURCE_8 = "com.mysql.cj.AbstractPreparedQuery";
	String MYSQL_CONNECTOR_5_0_SOURCE = EXEC_MYSQL_505;
	String MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE = EXEC_MYSQL_6X4;
	String MYSQL_CONNECTOR_5_1_SOURCE = EXEC_MYSQL_51X;
	String MYSQL_CONNECTOR_6_SOURCE = EXEC_MYSQL_6X3;
	String MYSQL_CONNECTOR_6_0_3_SOURCE = EXEC_MYSQL_6X2;
	String MYSQL_CONNECTOR_6_0_2_SOURCE = EXEC_MYSQL_6X;
	String MYSQL_CONNECTOR_8_SOURCE = EXEC_MYSQL_8X;
	List<String> MYSQL_SOURCE_METHOD_LIST = new ArrayList<String>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		{
			// Mysql Connector/J 5.0.5
			add(MYSQL_CONNECTOR_5_0_SOURCE);
			add(MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE);
			// Mysql Connector/J 5.1.x
			add(MYSQL_CONNECTOR_5_1_SOURCE);
			// Mysql Connector/J 6.x
			add(MYSQL_CONNECTOR_6_0_2_SOURCE);
			add(MYSQL_CONNECTOR_6_0_3_SOURCE);
			add(MYSQL_CONNECTOR_6_SOURCE);
			// Mysql Connector/J 8.x
			add(MYSQL_CONNECTOR_8_SOURCE);
		}
	};

	/** Mongo constants */

	String MONGO_NAMESPACE_FIELD = "namespace";
	String MONGO_COMMAND_FIELD = "command";
	String MONGO_PAYLOAD_FIELD = "payload";
	String MONGO_DELETE_REQUEST_FIELD = "deleteRequests";
	String MOGNO_ELEMENT_DATA_FIELD = "elementData";
	String MONGO_FILTER_FIELD = "filter";
	String MONGO_MULTIPLE_UPDATES_FIELD = "updates";
	String MONGO_SINGLE_UPDATE_FIELD = "update";
	String MONGO_INSERT_REQUESTS_FIELD = "insertRequests";
	String MONGO_DOCUMENT_FIELD = "document";
	String MONGO_WRITE_REQUEST_FIELD = "writeRequests";
	String MONGO_FIELD_NAME_FIELD = "fieldName";

	String MONGO_DELETE_CLASS_FRAGMENT = "Delete";
	String MONGO_UPDATE_CLASS_FRAGMENT = "Update";
	String MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT = "FindAndUpdateOperation";
	String MONGO_INSERT_CLASS_FRAGMENT = "Insert";
	String MONGO_FIND_CLASS_FRAGMENT = "Find";
	String MONGO_COMMAND_CLASS_FRAGMENT = "Command";
	String MONGO_WRITE_CLASS_FRAGMENT = "Write";
	String MONGO_DISTINCT_CLASS_FRAGMENT = "Distinct";

	String MONGO_COLLECTION_WILDCARD = "$cmd";
	String MONGO_COLLECTION_FIELD = "collectionName";
	String MONGO_COMMAND_NAME_FIELD = "commandName";

	/** Oracle DB constants */
	String ORACLE_DB_IDENTIFIER = "oracle.jdbc.driver";
	String ORACLE_CONNECTION_IDENTIFIER = "oracle.jdbc.driver.T4C8Oall";
	String ORACLE_STATEMENT_CLASS_IDENTIFIER = "oracle.jdbc.driver.OracleStatement";
	
	/** Http constants **/
	
	String GET_PATH = "getPath";
	String GET_HOST = "getHost";
	String GET_URI = "getURI";
	String EMPTY = "";
	String HTTP_TARGET_HOST = "http.target_host";
	String GET_ATTRIBUTE = "getAttribute";
	String REGEX_SPACE = "\\s+";
	String GET_REQUEST_LINE = "getRequestLine";
	String ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT = "org.apache.http.protocol.HttpContext";
	String ORG_APACHE_HTTP_HTTP_REQUEST = "org.apache.http.HttpRequest";
	String ORG_APACHE_COMMONS_HTTPCLIENT_URI = "org.apache.commons.httpclient.URI";
	String ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD = "org.apache.commons.httpclient.HttpMethod";

	ArrayList<String> ORACLE_CLASS_SKIP_LIST = new ArrayList<String>() {

		private static final long serialVersionUID = -1406453087946498488L;

		{
			add("oracle.jdbc.driver.T4C7Ocommoncall");
			add("oracle.jdbc.driver.T4CTTIoauthenticate");
			add("oracle.jdbc.driver.T4C7Oversion");
		}
	};

	String BYTE_ARRAY_CLASS = "[B";

	// ProcessorThread.java constants
	String JAVA_NET_URLCLASSLOADER = URL_CLASS_LOADER;
	String JAVA_NET_URLCLASSLOADER_NEWINSTANCE = EXEC_URL_CLASS_LOADER_NEW_INSTANCE;
	String USER_DIR = "user.dir";
	String PARAMVALUES = "paramValues";
	String PSQL_PARAMETER_REPLACEMENT = "\\?";

	String EMPTY_STRING = "";

	String SQL = "sql";

	String ORG_HSQLDB_STATEMENT = "org.hsqldb.Statement";

	String SQLOBJECT = "sqlObject";

	String ORACLESTATEMENT = "oracleStatement";

	String ZERO = "0";

	String NULL = "null";

	String CURSOR = "cursor";

	String FILE_URL = "file://";

	String DOTINSQUAREBRACKET = "[.]";

	String JAVA_LANG_RUNTIME = "java.lang.Runtime";

	String JAVA_IO_FILE = "java.io.File";

	// IPScheduledThread.java file constants
	String HOST_IP_PROPERTIES_FILE = "/etc/k2-adp/hostip.properties";

	String IPSCHEDULEDTHREAD_ = "ipScheduledThread-";
	String ACK_MSG = "ACK";

	// EventThreadPool.java file constants
	String K2_JAVA_AGENT = "K2-Java-Agent-";

	// LoggingInterceptor Constants
	char DIR_SEPERATOR = '/';
	String CGROUP_FILE_NAME = "/proc/self/cgroup";
	String DOCKER_DIR = "docker/";
	String KUBEPODS_DIR = "kubepods/";
	String LXC_DIR = "lxc/";
	String JAR_PATH_INIT_MSG = "Pooling getJarPathResultExecutorService to fetch results.";
	String JAR_PATH_FETCH_SUCCESS_MSG = "getJarPathResultExecutorService result fetched successfully.";
	String JAR_PATH_EMPTY_RESULT_ERR = "getJarPathResultExecutorService result is empty.";
	String JAR_PATH_TIMEOUT_ERR = "Timeout reached waiting for getJarPathResultExecutorService.";
	String HOST_PROP_FILE_NAME = "/etc/k2-adp/hostip.properties";
	String HOST_IP_FOUND_MSG = "hostip found: ";
	String JA_CONNECT_SUCCESS_MSG = "K2-JavaAgent installed successfully.";
	String PROC_DIR = "/proc/";
	String CMD_LINE_DIR = "/cmdline";
	String STAT = "/stat";
	String BYTE_BUFFER_FIELD_LIMIT = "limit";
	String BYTE_BUFFER_FIELD_POSITION = "position";
	String BYTE_BUFFER_FIELD_BUF = "buf";
	String BYTE_BUFFER_FIELD_LASTVALID = "lastValid";
	String BYTE_BUFFER_FIELD_HB = "hb";
	String TOMCAT_REQUEST_FIELD_INPUTBUFFER = "inputBuffer";
	String TOMCAT_REQUEST_FIELD_BYTEBUFFER = "byteBuffer";
	String COYOTE_ABSTRACT_INPUT_BUFFER_CLASS_NAME = "org.apache.coyote.http11.AbstractInputBuffer";
	String MYSQL_FIELD_ORIGINAL_SQL = "originalSql";
	String MYSQL_FIELD_QUERY = "query";
	String NEW_LINE_SEQUENCE = "\n";
	String TOMCAT_SERVER_INFO_CLASS_NAME = "org.apache.catalina.util.ServerInfo";
	String TOMCAT_FIELD_SERVERNUMBER = "serverNumber";
	String TOMCAT_VERSION_DETECTED_MSG = "Detected Tomcat Version ";
	String VERSION_SPLIT_EXPR = "\\.";
	String NULL_CHAR_AS_STRING = "\000";
	char VMPID_SPLIT_CHAR = '@';
	String APPLICATION_INFO_POSTED_MSG = "Posted application info : ";
	String COLON_SEPERATOR = ":";
	int TOMCAT_7 = 7;
	int TOMCAT_8 = 8;
	int TOMCAT_9 = 9;
	int K2_IC_TCP_PORT = 54321;
	
	String JSON_NAME_APPLICATION_INFO_BEAN = "applicationinfobean";
	String JSON_NAME_INTCODE_RESULT_BEAN = "EventBean";
	String JSON_NAME_HEALTHCHECK = "LAhealthcheck";
	String JSON_NAME_DYNAMICJARPATH_BEAN = "dynamicjarpathbean";
	String JSON_NAME_SHUTDOWN = "shutdown";
	
}