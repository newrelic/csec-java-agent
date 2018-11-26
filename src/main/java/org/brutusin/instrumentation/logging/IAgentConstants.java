package org.brutusin.instrumentation.logging;

public interface IAgentConstants {

	String TRACE_REGEX = "((?!org\\.apache\\.jsp.*))((^javax.*)|(^java\\.lang.*)|(^java\\.io.*)|(^org\\.apache.*)|(^java\\.nio.*)|(^java\\.util.*)|(^java\\.net.*)|(^sun.*)|(^java\\.security.*)|(^org\\.brutusin.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^org\\.hibernate.*)|(^java\\.sql.*)|(^com\\.mongodb.*)|(^org\\.apache\\.commons.*)|(^org\\.mongodb.*)|(^com\\.sun\\.org\\.apache.*)|(^com\\.sun\\.naming.*)|(^org\\.eclipse\\.jetty.*)|(^net\\.sourceforge\\.eclipsejetty.*)|(^java\\.awt.*)|(org\\.springframework.*)|(org\\.slf4j.*)|(com\\.sun\\.jmx.*)|(org\\.eclipse\\.jdt.*)|(com\\.opensymphony\\.xwork2.*)|(org\\.objectweb\\.asm.*)|(freemarker\\.cache.*))";

	String SYSYTEM_CALL_START = "static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException";

	String[][] SKIP_LIST = { { "sun.usagetracker.UsageTrackerClient", "run" },
			{ "java.lang.ClassLoader", "loadClass", "loadLibrary", "getResourceAsStream" }, { "java.io.DeleteOnExitHook", "runHooks" },
			{ "java.util.jar.JarFile", "<init>" }, { "java.util.logging.LogManager", "readConfiguration" },
			{ "org.apache.catalina.startup.Bootstrap", "<clinit>" },
			{ "org.apache.catalina.startup.ClassLoaderFactory", "createClassLoader", "validateFile" },
			{ "com.sun.org.apache.xerces.internal.utils.SecuritySupport", "readJAXPProperty" },
			{ "org.apache.catalina.startup.CatalinaProperties", "loadProperties" },
			{ "org.apache.catalina.startup.Catalina", "stopServer", "configFile", "initDirs" }, { "javax.xml.parsers.FactoryFinder", "find" },
			{ "org.apache.tomcat.util.modeler.Registry", "load" }, { "org.apache.catalina.startup.ContextConfig", "<clinit>" },
			{ "org.apache.tomcat.jni.Library", "<init>" }, { "org.apache.catalina.util.ServerInfo", "<clinit>" },
			{ "org.apache.catalina.util.ExtensionValidator", "addFolderList", "<clinit>" },
			{ "org.apache.catalina.core.StandardContext", "postWorkDirectory" }, { "org.apache.catalina.util.CharsetMapper", "<init>" },
			{ "org.apache.catalina.webresources.AbstractFileResourceSet", "initInternal" },
			{ "org.apache.catalina.webresources.StandardRoot", "createMainResourceSet" },
			{ "org.apache.catalina.startup.ContextConfig", "fixDocBase", "processContextConfig", "contextConfig" },
			{ "org.apache.catalina.core.StandardHost", "getConfigBaseFile", "getAppBaseFile" },
			{ "org.apache.tomcat.util.file.ConfigFileLoader", "getInputStream", "<clinit>" }, { "com.sun.naming.internal.VersionHelper12$4", "run" },
			{ "org.apache.catalina.startup.WebappServiceLoader", "parseConfigFile" },
			{ "org.apache.catalina.loader.WebappClassLoaderBase", "getResourceAsStream" }, { "org.apache.tomcat.util.buf.B2CConverter", "<clinit>" },
			{ "org.apache.catalina.startup.ContextConfig", "getDefaultWebXmlFragment", "getWebXmlSource", "<clinit>", "fixDocBase", "contextConfig",
					"processContextConfig" },
			{ "org.apache.catalina.authenticator.jaspic.AuthConfigFactoryImpl", "<clinit>" }, { "java.net.URL", "openConnection" } };


	String[] FILE_OPEN_EXECUTORS = { "public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" };


	String[] EXECUTORS = {
			SYSYTEM_CALL_START,
			
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
			"private <T> T com.mongodb.connection.DefaultServerConnection.executeProtocol(com.mongodb.connection.Protocol<T>)",
			
			// mssql calls
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException,java.sql.SQLTimeoutException",
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException",
			
			// mysql calls
			"final com.mysql.jdbc.ResultSet com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.Statement,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,com.mysql.jdbc.Connection,int,int,boolean,java.lang.String,boolean) throws java.lang.Exception",	// Mysql Connector/J 5.0.5
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception",	// Mysql Connector/J 5.1.x
			"public final <T> T com.mysql.cj.mysqla.io.MysqlaProtocol.sqlQueryDirect(com.mysql.cj.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.cj.api.mysqla.io.PacketPayload,int,boolean,java.lang.String,com.mysql.cj.api.mysqla.result.ColumnDefinition,com.mysql.cj.api.io.Protocol$GetProfilerEventHandlerInstanceFunction,com.mysql.cj.api.mysqla.io.ProtocolEntityFactory<T>) throws java.io.IOException", // Mysql Connector/J 6.x
			"public <T> T com.mysql.cj.NativeSession.execSQL(com.mysql.cj.Query,java.lang.String,int,com.mysql.cj.protocol.a.NativePacketPayload,boolean,com.mysql.cj.protocol.ProtocolEntityFactory<T, com.mysql.cj.protocol.a.NativePacketPayload>,java.lang.String,com.mysql.cj.protocol.ColumnDefinition,boolean)", // Mysql Connector/J 8.x
			
//			// FileWriter
//			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
//			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" 
			};

	String MSSQL_EXECUTOR = "boolean com.microsoft.sqlserver.jdbc.SQLServerConnection.executeCommand(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String[] CONSTRUCTOR = { "<init>" };
	
	String[] ALL_CLASSES = { 
				"com/mysql/jdbc/MysqlIO", 
				"java/lang/ProcessImpl", 
				// FileWriter
				"java/nio/file/spi/FileSystemProvider", 
				"java/io/File", 
				"com/microsoft/sqlserver/jdbc/SQLServerStatement",
				"com/mysql/cj/mysqla/io/MysqlaProtocol", 
				"com/mysql/cj/NativeSession",
				"com/mongodb/connection/DefaultServerConnection",
				"com/mongodb/internal/connection/DefaultServerConnection",
				"com/mongodb/async/client/MongoClientImpl$2",
				"com/mongodb/async/client/AsyncOperationExecutorImpl",
				"com/mongodb/async/client/OperationExecutorImpl",
			};

	String[][] ALL_METHODS = { 
				{ "sqlQueryDirect" },
				{ "start" }, 
				{ "newOutputStream" }, 
				CONSTRUCTOR , 
				{"executeStatement"}, 
				{"sqlQueryDirect"}, 
				{"execSQL"},
				{ "executeProtocol"  },
				{ "executeProtocol" },
				{ "execute" },
				{ "execute" },
				{ "execute" },
			};
}
