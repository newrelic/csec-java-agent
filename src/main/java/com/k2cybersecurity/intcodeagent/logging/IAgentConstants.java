package com.k2cybersecurity.intcodeagent.logging;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public interface IAgentConstants {

	String TRACE_REGEX = "((?!(org\\.apache\\.jsp.*)|(javax\\.servlet\\.http.*)))((^javax.*)|(^java\\.lang.*)|(^java\\.io.*)|(^org\\.apache.*)|(^java\\.nio.*)|(^java\\.util.*)|(^java\\.net.*)|(^sun.*)|(^java\\.security.*)|(^k2\\.org\\.brutusin.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^org\\.hibernate.*)|(^java\\.sql.*)|(^com\\.mongodb.*)|(^org\\.apache\\.commons.*)|(^org\\.mongodb.*)|(^com\\.sun.*)|(^org\\.eclipse\\.jetty.*)|(^net\\.sourceforge\\.eclipsejetty.*)|(^java\\.awt.*)|(^org\\.springframework.*)|(^org\\.slf4j.*)|(^org\\.eclipse\\.jdt.*)|(^com\\.opensymphony\\.xwork2.*)|(^k2\\.org\\.objectweb\\.asm.*)|(^freemarker\\.cache.*)|(^com\\.mchange.*)|(^org\\.postgresql.*)|(^oracle\\.jdbc.*)|(^org\\.hsqldb.*)|(^ch\\.qos\\.logback.*)|(^io\\.micrometer.*)|(^k2\\.org\\.json.*)|(^k2\\.com\\.fasterxml.*))";

	String SYSYTEM_CALL_START = "static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException";

	List<String> FILE_OPEN_EXECUTORS = Arrays.asList(new String[] {
			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" });

	Map<String, List<String>> MYSQL_GET_CONNECTION_MAP = new HashMap() {
		{
			put("java.sql.DriverManager", Collections.singletonList("getConnection"));
			put("com.mysql.jdbc.ConnectionImpl", Arrays.asList("getInstance", "isReadOnly"));
		}
	};

	String[] MONGO_EXECUTORS = {
			// asynchronous mongo calls
			"public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",

			// synchronous mongo calls
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.LegacyProtocol<T>)",
			"private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
			"private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.LegacyProtocol<T>)",
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.Protocol<T>)" };
		
	String SERVLET_REQUEST_FACADE = "public org.apache.catalina.connector.RequestFacade(org.apache.catalina.connector.Request)";
	
	String PSQLV3_EXECUTOR = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.v3.V3Query,org.postgresql.core.v3.V3ParameterList,int,int,int,org.postgresql.core.v3.QueryExecutorImpl$ErrorTrackingResultHandler) throws java.io.IOException,java.sql.SQLException";
	
	String PSQLV2_EXECUTOR = "protected void org.postgresql.core.v2.QueryExecutorImpl.sendQuery(org.postgresql.core.v2.V2Query,org.postgresql.core.v2.SimpleParameterList,java.lang.String) throws java.io.IOException";
	
	String PSQL42_EXECUTOR = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.Query,org.postgresql.core.v3.V3ParameterList,int,int,int,org.postgresql.core.ResultHandler,org.postgresql.jdbc.BatchResultHandler) throws java.io.IOException,java.sql.SQLException";
	
	// Postgres V3 API : > Server 7.4 < Server 9.X
	String PSQLV3_EXECUTOR7_4 = "private void org.postgresql.core.v3.QueryExecutorImpl.sendQuery(org.postgresql.core.v3.V3Query,org.postgresql.core.v3.V3ParameterList,int,int,int) throws java.io.IOException,java.sql.SQLException";
	
	//HSQL_DB v2.4
	String HSQL_V2_4 = "public org.hsqldb.result.Result org.hsqldb.Session.executeCompiledStatement(org.hsqldb.Statement,java.lang.Object[],int)";
		
	
	String[] EXECUTORS = { SYSYTEM_CALL_START,

			// mssql calls
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException,java.sql.SQLTimeoutException",
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException",

			// mysql calls
			// Mysql Connector/J 5.0.5
			"final com.mysql.jdbc.ResultSet com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.Statement,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,com.mysql.jdbc.Connection,int,int,boolean,java.lang.String,boolean) throws java.lang.Exception",
			// Mysql Connector/J 5.1.x
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception",
			// Mysql Connector/J 6.x
			"public final com.mysql.cj.api.jdbc.ResultSetInternalMethods com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.mysqla.io.Buffer,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[])",
			"public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[],com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction)",
			"public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,boolean,java.lang.String,com.mysql.cj.api.mysqla.result.ColumnDefinition,com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction,com.mysql.cj.api.mysqla.io.ProtocolEntityFactory<T>) throws java.io.IOException",
			"private com.mysql.jdbc.ResultSet com.mysql.jdbc.ServerPreparedStatement.serverExecute(int,boolean) throws java.sql.SQLException",
			
			// Mysql Connector/J 8.x
			"public <T> T com.mysql.cj.NativeSession.execSQL(com.mysql.cj.Query,java.lang.String,int,com.mysql.cj.protocol.a.NativePacketPayload,boolean,com.mysql.cj.protocol.ProtocolEntityFactory<T, com.mysql.cj.protocol.a.NativePacketPayload>,java.lang.String,com.mysql.cj.protocol.ColumnDefinition,boolean)",

			// oracle db
			"final void oracle.jdbc.driver.T4CTTIfun.doRPC() throws java.io.IOException,java.sql.SQLException",

			//postgresql
			PSQLV3_EXECUTOR,
			PSQLV2_EXECUTOR ,
			PSQL42_EXECUTOR,
			PSQLV3_EXECUTOR7_4,
			
			//HSQLDB
			HSQL_V2_4,
			
			// // FileWriter
//			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
//			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)",

			// dynamic class loading
			"public java.net.URLClassLoader(java.net.URL[])",
			"private java.lang.Class<?> java.net.URLClassLoader.defineClass(java.lang.String,sun.misc.Resource) throws java.io.IOException",
			"public static java.net.URLClassLoader java.net.URLClassLoader.newInstance(java.net.URL[])",

			// File Input
			// "public java.io.FileInputStream(java.lang.String) throws
			// java.io.FileNotFoundException",
			// "public java.io.FileInputStream(java.io.File) throws
			// java.io.FileNotFoundException",

			// http request
//			"protected void javax.servlet.http.HttpServlet.service(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws javax.servlet.ServletException,java.io.IOException",

	};

	String HTTP_SERVLET_SERVICE = "protected void javax.servlet.http.HttpServlet.service(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws javax.servlet.ServletException,java.io.IOException";

	String STRUTS2_DO_FILTER = "public void org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter.doFilter(javax.servlet.ServletRequest,javax.servlet.ServletResponse,javax.servlet.FilterChain) throws java.io.IOException,javax.servlet.ServletException";

	String MSSQL_EXECUTOR = "boolean com.microsoft.sqlserver.jdbc.SQLServerConnection.executeCommand(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";
	

	String[] CONSTRUCTOR = { "<init>" };

	String[] ALL_CLASSES = { "com/mysql/jdbc/MysqlIO", "java/lang/ProcessImpl",
			// FileWriter
//			"java/nio/file/spi/FileSystemProvider", "java/io/File", 

			// SQL
			"com/microsoft/sqlserver/jdbc/SQLServerStatement", "com/mysql/cj/mysqla/io/MysqlaProtocol",
			"com/mysql/cj/NativeSession","com/mysql/jdbc/ServerPreparedStatement",

			// Mongo
			"com/mongodb/connection/DefaultServerConnection", "com/mongodb/internal/connection/DefaultServerConnection",
			"com/mongodb/async/client/MongoClientImpl$2", "com/mongodb/async/client/AsyncOperationExecutorImpl",
			"com/mongodb/async/client/OperationExecutorImpl", "java/net/URLClassLoader",
			
			// Oracle DB
			"oracle/jdbc/driver/T4CTTIfun",
			
			// http request
//			"javax/servlet/http/HttpServlet",
			"org/apache/catalina/connector/CoyoteAdapter", "org/apache/catalina/connector/InputBuffer",
			"org/eclipse/jetty/server/handler/HandlerWrapper", "org/eclipse/jetty/http/HttpParser",
//			"javax/faces/webapp/FacesServlet",
//			"org/apache/struts2/dispatcher/ng/filter/StrutsPrepareAndExecuteFilter"		

			// Postgresql
			"org/postgresql/core/v3/QueryExecutorImpl", "org/postgresql/core/v2/QueryExecutorImpl", 
			
			//HSQLDB
			"org/hsqldb/Session"
			
			};

	String[][] ALL_METHODS = { { "sqlQueryDirect" }, { "start" },
			
			// SQL
//			{ "newOutputStream" }, CONSTRUCTOR,
			{ "executeStatement" }, { "sqlQueryDirect" }, { "execSQL" },{ "serverExecute" },
			
			// mongodb
			{ "executeProtocol" }, { "executeProtocol" },
			{ "execute" }, { "execute" }, { "execute" }, { "<init>", "newInstance" },
			
			//Oracle methods
			{ "doRPC" },

//			{ "service" },
			{ "service" }, { "setByteBuffer" }, { "handle" }, { "parseNext" },
//			{ "service" },
//			{ "doFilter" }
			// postgresql
			{ "sendQuery" }, { "sendQuery" },
			
			//HSQLDB
			{"executeCompiledStatement"}
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
	String JETTY_REQUEST_HANDLE = "public void org.eclipse.jetty.server.handler.HandlerWrapper.handle(java.lang.String,org.eclipse.jetty.server.Request,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse) throws java.io.IOException,javax.servlet.ServletException";
	String JETTY_PARSE_NEXT = "public boolean org.eclipse.jetty.http.HttpParser.parseNext(java.nio.ByteBuffer)";

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
	String MYSQL_CONNECTOR_5_0_SOURCE = "final com.mysql.jdbc.ResultSet com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.Statement,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,com.mysql.jdbc.Connection,int,int,boolean,java.lang.String,boolean) throws java.lang.Exception";
	String MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE = "private com.mysql.jdbc.ResultSet com.mysql.jdbc.ServerPreparedStatement.serverExecute(int,boolean) throws java.sql.SQLException";
	String MYSQL_CONNECTOR_5_1_SOURCE = "final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception";
	String MYSQL_CONNECTOR_6_SOURCE = "public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,boolean,java.lang.String,com.mysql.cj.api.mysqla.result.ColumnDefinition,com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction,com.mysql.cj.api.mysqla.io.ProtocolEntityFactory<T>) throws java.io.IOException";
	String MYSQL_CONNECTOR_6_0_3_SOURCE = "public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[],com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction)";
	String MYSQL_CONNECTOR_6_0_2_SOURCE = "public final com.mysql.cj.api.jdbc.ResultSetInternalMethods com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.mysqla.io.Buffer,int,int,int,boolean,java.lang.String,com.mysql.cj.core.result.Field[])";
	String MYSQL_CONNECTOR_8_SOURCE = "public <T> T com.mysql.cj.NativeSession.execSQL(com.mysql.cj.Query,java.lang.String,int,com.mysql.cj.protocol.a.NativePacketPayload,boolean,com.mysql.cj.protocol.ProtocolEntityFactory<T, com.mysql.cj.protocol.a.NativePacketPayload>,java.lang.String,com.mysql.cj.protocol.ColumnDefinition,boolean)";
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

	
	ArrayList ORACLE_CLASS_SKIP_LIST = new ArrayList<String>(){
		
		private static final long serialVersionUID = -1406453087946498488L;

	{
		add("oracle.jdbc.driver.T4C7Ocommoncall");
		add("oracle.jdbc.driver.T4CTTIoauthenticate");
		add("oracle.jdbc.driver.T4C7Oversion");
	}};
	
	String BYTE_ARRAY_CLASS = "[B";
	
	
	// ProcessorThread.java constants
	String JAVA_NET_URLCLASSLOADER = "public java.net.URLClassLoader(java.net.URL[])";
	String JAVA_NET_URLCLASSLOADER_NEWINSTANCE = "public static java.net.URLClassLoader java.net.URLClassLoader.newInstance(java.net.URL[])";
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

	String COLON = ":";

	// IPScheduledThread.java file constants
	String HOST_IP_PROPERTIES_FILE = "/etc/k2-adp/hostip.properties";

	String IPSCHEDULEDTHREAD_ = "ipScheduledThread-";

	// EventThreadPool.java file constants
	String K2_JAVA_AGENT = "K2-Java-Agent-";
	
	//AgentBasicInfo.java file constants
	String K2_JAVAAGENT_PROPERTIES = "k2-javaagent.properties";

	String K2_JAVAAGENT_VERSION = "k2.javaagent.version";

	String K2_JAVAAGENT_TOOL_ID = "k2.javaagent.tool.id";

	String K2_JAVAAGENT_JSONNAME_APPLICATIONINFOBEAN = "k2.javaagent.jsonname.applicationinfobean";

	String K2_JAVAAGENT_JSONNAME_INTCODERESULTBEAN = "k2.javaagent.jsonname.intcoderesultbean";

	String K2_JAVAAGENT_JSONNAME_JARPATHBEAN = "k2.javaagent.jsonname.jarpathbean";

	String K2_JAVAAGENT_JSONNAME_DYNAMICJARPATHBEAN = "k2.javaagent.jsonname.dynamicjarpathbean";
}