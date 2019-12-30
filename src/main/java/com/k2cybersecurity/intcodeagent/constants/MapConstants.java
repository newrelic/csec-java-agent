package com.k2cybersecurity.intcodeagent.constants;

import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.util.*;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public abstract class MapConstants {
	public static Map<String, List<String>> MYSQL_GET_CONNECTION_MAP = new HashMap<>();

	public static Map<String, List<String>> HSQL_GET_CONNECTION_MAP = new HashMap<>();

	public static Map<String, VulnerabilityCaseType> MONGO_EXECUTORS = new HashMap<>();

	// MSSQL
	public static Map<String, VulnerabilityCaseType> FILE_EXECUTORS = new HashMap<>();


	public static Map<String, List<String>> INSTRUMENTED_METHODS = new HashMap<>();

	public static Map<String, VulnerabilityCaseType> EXECUTORS = new HashMap<>();

	public static List<String> MYSQL_SOURCE_METHOD_LIST = new ArrayList<>();

	public static ArrayList<String> ORACLE_CLASS_SKIP_LIST = new ArrayList<>();

	static {
		MYSQL_GET_CONNECTION_MAP.put("java.sql.DriverManager", Collections.singletonList("getConnection"));
		MYSQL_GET_CONNECTION_MAP.put("com.mysql.jdbc.ConnectionImpl", Arrays.asList("getInstance", "isReadOnly"));

		HSQL_GET_CONNECTION_MAP.put("org.hsqldb.jdbc.JDBCDriver", Collections.singletonList("getConnection"));

		// asynchronous mongo calls
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.MongoClientImpl$2.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.AsyncOperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.session.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncReadOperation<T>,com.mongodb.ReadPreference,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("public <T> void com.mongodb.async.client.OperationExecutorImpl.execute(com.mongodb.operation.AsyncWriteOperation<T>,com.mongodb.ReadConcern,com.mongodb.async.client.ClientSession,com.mongodb.async.SingleResultCallback<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		// synchronous mongo calls
		MONGO_EXECUTORS.put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.LegacyProtocol<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.CommandProtocol<T>,com.mongodb.session.SessionContext)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("private <T> T com.mongodb.internal.connection.DefaultServerConnection.executeProtocol(com.mongodb.internal.connection.LegacyProtocol<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);
		MONGO_EXECUTORS.put("private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.Protocol<T>)",
				VulnerabilityCaseType.NOSQL_DB_COMMAND);

		FILE_EXECUTORS.put(JAVA_IO_FILE_INPUTSTREAM_OPEN, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_IO_FILE_OUTPUTSTREAM_OPEN, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_OPEN, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_FOPEN, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_LINK, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_UNLINK, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_MKNOD, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_RENAME, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_MKDIR, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_RMDIR, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_SYMLINK, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_CHOWN, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_NIO_UNIX_CHMOD, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_IO_UNIX_FS_DELETE, VulnerabilityCaseType.FILE_OPERATION);
		FILE_EXECUTORS.put(JAVA_IO_RANDOM_ACCESS_FILE_OPEN, VulnerabilityCaseType.FILE_OPERATION);

//		INSTRUMENTED_METHODS.put(CLASS_JAVA_LANG_PROCESS_IMPL, Collections.singletonList("start"));
//		INSTRUMENTED_METHODS.put(CLASS_COM_MICROSOFT_SQLSERVER_JDBC_SQL_SERVER_STATEMENT, Collections.singletonList("executeStatement"));
//		INSTRUMENTED_METHODS.put(CLASS_COM_MYSQL_CJ_MYSQLA_IO_MYSQLA_PROTOCOL, Collections.singletonList("sqlQueryDirect"));
//		INSTRUMENTED_METHODS.put(CLASS_COM_MYSQL_JDBC_MYSQL_IO, Collections.singletonList("sqlQueryDirect"));
//		INSTRUMENTED_METHODS.put(CLASS_COM_MYSQL_CJ_NATIVE_SESSION, Collections.singletonList("execSQL"));
//		INSTRUMENTED_METHODS.put(CLASS_COM_MYSQL_JDBC_SERVER_PREPARED_STATEMENT, Collections.singletonList("serverExecute"));
		INSTRUMENTED_METHODS.put(CLASS_COM_MONGODB_CONNECTION_DEFAULT_SERVER_CONNECTION, Collections.singletonList("executeProtocol"));
		INSTRUMENTED_METHODS.put(CLASS_COM_MONGODB_INTERNAL_CONNECTION_DEFAULT_SERVER_CONNECTION,Collections.singletonList("executeProtocol"));
		INSTRUMENTED_METHODS.put(CLASS_COM_MONGODB_ASYNC_CLIENT_MONGO_CLIENT_IMPL$2, Collections.singletonList("execute"));
		INSTRUMENTED_METHODS.put(CLASS_COM_MONGODB_ASYNC_CLIENT_ASYNC_OPERATION_EXECUTOR_IMPL, Collections.singletonList("execute"));
		INSTRUMENTED_METHODS.put(CLASS_COM_MONGODB_ASYNC_CLIENT_OPERATION_EXECUTOR_IMPL, Collections.singletonList("execute"));
		INSTRUMENTED_METHODS.put(CLASS_JAVA_NET_URL_CLASS_LOADER, Arrays.asList(new String[] { "<init>", "newInstance" }));
		INSTRUMENTED_METHODS.put(CLASS_ORACLE_JDBC_DRIVER_T4CTT_IFUN, Collections.singletonList("doRPC"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_APACHE_CATALINA_CONNECTOR_COYOTE_ADAPTER, Collections.singletonList("service"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_APACHE_CATALINA_CONNECTOR_INPUT_BUFFER, Collections.singletonList("setByteBuffer"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_ECLIPSE_JETTY_SERVER_HTTP_CONNECTION, Collections.singletonList("onFillable"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_ECLIPSE_JETTY_HTTP_HTTP_PARSER, Collections.singletonList("parseNext"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL, Collections.singletonList("sendQuery"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL, Collections.singletonList("sendQuery"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_HSQLDB_SESSION, Arrays.asList(new String[] { "executeCompiledStatement", "execute" }));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION, Collections.singletonList("execute"));
//		INSTRUMENTED_METHODS.put(CLASS_ORG_HSQLDB_CLIENT_CONNECTION,Arrays.asList(new String[] { "execute" }));
//		INSTRUMENTED_METHODS.put(COM_IBM_WS_GENERICBNF_INTERNAL_BNFHEADERSIMPL, Collections.singletonList("fillByteCache"));
//		INSTRUMENTED_METHODS.put(COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTPINBOUNDLINK, Collections.singletonList("processRequest"));
//		INSTRUMENTED_METHODS.put(COM_IBM_WS_GENERICBNF_IMPL_BNFHEADERSIMPL, Collections.singletonList("fillByteCache"));
//		INSTRUMENTED_METHODS.put(COM_IBM_WS_HTTP_CHANNEL_INBOUND_IMPL_HTTPINBOUNDLINK, Collections.singletonList("processRequest"));
//		INSTRUMENTED_METHODS.put(IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER, Collections.singletonList("handleRequest"));
		INSTRUMENTED_METHODS.put(CLASS_HTTP_REQUEST_EXECUTOR, Collections.singletonList("doSendRequest"));
		INSTRUMENTED_METHODS.put(CLASS_JAVA_HTTP_HANDLER, Collections.singletonList("openConnection"));
		INSTRUMENTED_METHODS.put(CLASS_JAVA_HTTPS_HANDLER, Collections.singletonList("openConnection"));
		INSTRUMENTED_METHODS.put(CLASS_JAVA_SSL_HTTPS_HANDLER, Collections.singletonList("openConnection"));
		INSTRUMENTED_METHODS.put(CLASS_JDK_INCUBATOR_HTTP_MULTIEXCHANGE, Arrays.asList(new String[] { "response", "responseAsync", "multiResponseAsync" }));
		INSTRUMENTED_METHODS.put(CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT, Collections.singletonList("execute"));
		INSTRUMENTED_METHODS.put(CLASS_APACHE_COMMONS_HTTP_METHOD_DIRECTOR, Collections.singletonList("executeWithRetry"));
		INSTRUMENTED_METHODS.put(CLASS_OKHTTP_HTTP_ENGINE, Collections.singletonList("sendRequest"));
		INSTRUMENTED_METHODS.put(CLASS_WEBLOGIC_HTTP_HANDLER, Collections.singletonList("openConnection"));
//		INSTRUMENTED_METHODS.put(CLASS_JAVA_IO_FILE_OUTPUT_STREAM, Collections.singletonList("open"));
//		INSTRUMENTED_METHODS.put(CLASS_JAVA_IO_FILE_INPUT_STREAM, Collections.singletonList("open"));
//		INSTRUMENTED_METHODS.put(CLASS_SUN_NIO_FS_UNIX_NATIVE_DISPATCHER, Arrays.asList(new String[] {"open", "fopen", "link", "unlink", "mknod", "rename", "mkdir", "rmdir", "symlink", "chown", "chmod"}));
		INSTRUMENTED_METHODS.put("org/xnio/XnioWorker", Collections.singletonList("execute"));
//		INSTRUMENTED_METHODS.put(JAVA_IO_UNIX_FILE_SYSTEM, Collections.singletonList("delete"));
//		INSTRUMENTED_METHODS.put(JAVA_IO_RANDOM_ACCESS_FILE, Collections.singletonList("open"));




		// System Command
		EXECUTORS.put(SYSYTEM_CALL_START, VulnerabilityCaseType.SYSTEM_COMMAND);

		// MSSQL
		EXECUTORS.put(EXEC_MSSQL_SQLTIMEOUT, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MSSQL, VulnerabilityCaseType.SQL_DB_COMMAND);

		// MYSQL
		EXECUTORS.put(EXEC_MYSQL_505, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_51X, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_6X, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_6X2, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_6X3, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_6X4, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(EXEC_MYSQL_8X, VulnerabilityCaseType.SQL_DB_COMMAND);

		// ORACLE
		EXECUTORS.put(EXEC_ORACLE, VulnerabilityCaseType.SQL_DB_COMMAND);

		// postgresql
		EXECUTORS.put(PSQLV3_EXECUTOR, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(PSQLV2_EXECUTOR, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(PSQL42_EXECUTOR, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(PSQLV3_EXECUTOR7_4, VulnerabilityCaseType.SQL_DB_COMMAND);

		// HSQLDB
		EXECUTORS.put(HSQL_V2_4, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(HSQL_V1_8_CONNECTION, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(HSQL_V1_8_SESSION, VulnerabilityCaseType.SQL_DB_COMMAND);
		EXECUTORS.put(HSQL_V2_3_4_CLIENT_CONNECTION, VulnerabilityCaseType.SQL_DB_COMMAND);

		// MongoDB
		EXECUTORS.putAll(MONGO_EXECUTORS);

		// dynamic class loading
		EXECUTORS.put(URL_CLASS_LOADER, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);
		EXECUTORS.put(EXEC_DEFINE_CLASS, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);
		EXECUTORS.put(EXEC_URL_CLASS_LOADER_NEW_INSTANCE, VulnerabilityCaseType.DYNAMIC_CLASS_LOADING);

		// http request
		EXECUTORS.put(APACHE_HTTP_REQUEST_EXECUTOR_METHOD, VulnerabilityCaseType.HTTP_REQUEST);

		//JAVA_OPEN_CONNECTION_METHOD,
		EXECUTORS.put(JAVA_OPEN_CONNECTION_METHOD2, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(JAVA_OPEN_CONNECTION_METHOD2_HTTPS, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD, VulnerabilityCaseType.HTTP_REQUEST);

		EXECUTORS.putAll(FILE_EXECUTORS);

		EXECUTORS.put(APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(OKHTTP_HTTP_ENGINE_METHOD, VulnerabilityCaseType.HTTP_REQUEST);
		EXECUTORS.put(WEBLOGIC_OPEN_CONNECTION_METHOD, VulnerabilityCaseType.HTTP_REQUEST);

		// Mysql Connector/J 5.0.5
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_5_0_SOURCE);
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE);
		// Mysql Connector/J 5.1.x
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_5_1_SOURCE);
		// Mysql Connector/J 6.x
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_6_0_2_SOURCE);
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_6_0_3_SOURCE);
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_6_SOURCE);
		// Mysql Connector/J 8.x
		MYSQL_SOURCE_METHOD_LIST.add(MYSQL_CONNECTOR_8_SOURCE);


		ORACLE_CLASS_SKIP_LIST.add("oracle.jdbc.driver.T4C7Ocommoncall");
		ORACLE_CLASS_SKIP_LIST.add("oracle.jdbc.driver.T4CTTIoauthenticate");
		ORACLE_CLASS_SKIP_LIST.add("oracle.jdbc.driver.T4C7Oversion");
	}
}
