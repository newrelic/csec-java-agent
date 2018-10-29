package org.brutusin.instrumentation.logging;

public interface IAgentConstants {

	String TRACE_REGEX = "((?!org\\.apache\\.jsp.*))((^javax.*)|(^java\\.lang.*)|(^java\\.io.*)|(^org\\.apache.*)|(^java\\.nio.*)|(^java\\.util.*)|(^java\\.net.*)|(^sun.*)|(^java\\.security.*)|(^org\\.brutusin.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^java\\.sql.*)|(com\\.mongodb.*)|(org\\.apache\\.commons.*)|(org\\.mongodb.*)|(^com\\.sun\\.org\\.apache.*)|(^com\\.sun\\.naming.*)|(^org\\.eclipse\\.jetty.*)|(^net\\.sourceforge\\.eclipsejetty.*)|(^java\\.awt.*)|(org\\.springframework.*)|(org\\.slf4j.*)|(com\\.sun\\.jmx.*)|(org\\.eclipse\\.jdt.*)|(com\\.opensymphony\\.xwork2.*)|(org\\.objectweb\\.asm.*)|(freemarker\\.cache.*))";

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

	String[] COMPLETE_LIST = {
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception",
			SYSYTEM_CALL_START,
			"final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException",
			"void com.microsoft.sqlserver.jdbc.TDSWriter.writeString(java.lang.String) throws com.microsoft.sqlserver.jdbc.SQLServerException",
			"java.lang.String com.microsoft.sqlserver.jdbc.SQLServerConnection.replaceParameterMarkers(java.lang.String,com.microsoft.sqlserver.jdbc.Parameter[],boolean) throws com.microsoft.sqlserver.jdbc.SQLServerException",
			"private final boolean com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement.buildPreparedStrings(com.microsoft.sqlserver.jdbc.Parameter[],boolean) throws com.microsoft.sqlserver.jdbc.SQLServerException",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.insertCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.InsertRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.insertCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.InsertRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.insertAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.InsertRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.insert(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.InsertRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.insert(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.InsertRequest)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.update(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.UpdateRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.update(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.UpdateRequest)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.delete(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.delete(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.DeleteRequest)",
			"public <T> T com.mongodb.connection.DefaultServerConnection.command(java.lang.String,org.bson.BsonDocument,boolean,org.bson.FieldNameValidator,org.bson.codecs.Decoder<T>)",
			"public <T> T com.mongodb.connection.DefaultServerConnection.command(java.lang.String,org.bson.BsonDocument,org.bson.FieldNameValidator,com.mongodb.ReadPreference,org.bson.codecs.Decoder<T>,com.mongodb.session.SessionContext,boolean,com.mongodb.connection.SplittablePayload,org.bson.FieldNameValidator)",
			"public void com.mongodb.connection.DefaultServerConnection.updateAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.UpdateRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.updateAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.UpdateRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.DeleteRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.updateCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.UpdateRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.updateCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.UpdateRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.deleteCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.commandAsync(java.lang.String,org.bson.BsonDocument,boolean,org.bson.FieldNameValidator,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.commandAsync(java.lang.String,org.bson.BsonDocument,org.bson.FieldNameValidator,com.mongodb.ReadPreference,org.bson.codecs.Decoder<T>,com.mongodb.session.SessionContext,boolean,com.mongodb.connection.SplittablePayload,org.bson.FieldNameValidator,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> com.mongodb.connection.QueryResult<T> com.mongodb.connection.DefaultServerConnection.query(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>)",
			"public <T> com.mongodb.connection.QueryResult<T> com.mongodb.connection.DefaultServerConnection.query(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.queryAsync(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<com.mongodb.connection.QueryResult<T>>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.queryAsync(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<com.mongodb.connection.QueryResult<T>>)",

			// FileWriter
//			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
//			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" 
			};

	String[] FILE_OPEN_EXECUTORS = { "public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" };

	String[] ALL_CLASSES = { "com/mysql/jdbc/MysqlIO", "java/lang/ProcessImpl", "com/microsoft/sqlserver/jdbc/SQLServerStatement",
			"com/microsoft/sqlserver/jdbc/TDSWriter", "com/microsoft/sqlserver/jdbc/SQLServerConnection",
			"com/microsoft/sqlserver/jdbc/SQLServerPreparedStatement", "com/mongodb/connection/DefaultServerConnection",
			// FileWriter
			"java/nio/file/spi/FileSystemProvider", "java/io/File" };

	String[] EXECUTORS = {
			SYSYTEM_CALL_START,
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.insertCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.InsertRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.insertCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.InsertRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.insertAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.InsertRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.insert(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.InsertRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.insert(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.InsertRequest)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.update(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.UpdateRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.update(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.UpdateRequest)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.delete(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>)",
			"public com.mongodb.WriteConcernResult com.mongodb.connection.DefaultServerConnection.delete(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.DeleteRequest)",
			"public <T> T com.mongodb.connection.DefaultServerConnection.command(java.lang.String,org.bson.BsonDocument,boolean,org.bson.FieldNameValidator,org.bson.codecs.Decoder<T>)",
			"public <T> T com.mongodb.connection.DefaultServerConnection.command(java.lang.String,org.bson.BsonDocument,org.bson.FieldNameValidator,com.mongodb.ReadPreference,org.bson.codecs.Decoder<T>,com.mongodb.session.SessionContext,boolean,com.mongodb.connection.SplittablePayload,org.bson.FieldNameValidator)",
			"public void com.mongodb.connection.DefaultServerConnection.updateAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.UpdateRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.updateAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.UpdateRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.bulk.DeleteRequest,com.mongodb.async.SingleResultCallback<com.mongodb.WriteConcernResult>)",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.updateCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.UpdateRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.updateCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.lang.Boolean,java.util.List<com.mongodb.bulk.UpdateRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public com.mongodb.bulk.BulkWriteResult com.mongodb.connection.DefaultServerConnection.deleteCommand(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>)",
			"public void com.mongodb.connection.DefaultServerConnection.deleteCommandAsync(com.mongodb.MongoNamespace,boolean,com.mongodb.WriteConcern,java.util.List<com.mongodb.bulk.DeleteRequest>,com.mongodb.async.SingleResultCallback<com.mongodb.bulk.BulkWriteResult>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.commandAsync(java.lang.String,org.bson.BsonDocument,boolean,org.bson.FieldNameValidator,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.commandAsync(java.lang.String,org.bson.BsonDocument,org.bson.FieldNameValidator,com.mongodb.ReadPreference,org.bson.codecs.Decoder<T>,com.mongodb.session.SessionContext,boolean,com.mongodb.connection.SplittablePayload,org.bson.FieldNameValidator,com.mongodb.async.SingleResultCallback<T>)",
			"public <T> com.mongodb.connection.QueryResult<T> com.mongodb.connection.DefaultServerConnection.query(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>)",
			"public <T> com.mongodb.connection.QueryResult<T> com.mongodb.connection.DefaultServerConnection.query(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.queryAsync(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<com.mongodb.connection.QueryResult<T>>)",
			"public <T> void com.mongodb.connection.DefaultServerConnection.queryAsync(com.mongodb.MongoNamespace,org.bson.BsonDocument,org.bson.BsonDocument,int,int,int,boolean,boolean,boolean,boolean,boolean,boolean,org.bson.codecs.Decoder<T>,com.mongodb.async.SingleResultCallback<com.mongodb.connection.QueryResult<T>>)",
			// FileWriter
//			"public java.io.OutputStream java.nio.file.spi.FileSystemProvider.newOutputStream(java.nio.file.Path,java.nio.file.OpenOption...) throws java.io.IOException",
//			"public java.io.File(java.lang.String,java.lang.String)", "public java.io.File(java.lang.String)" 
			};

	String MSSQL_EXECUTOR = "final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String[] CONSTRUCTOR = { "<init>" };

	String[][] ALL_METHODS = { { "sqlQueryDirect" }, { "start" }, { "executeStatement", "replaceMarkerWithNull" }, { "writeString" },
			{ "replaceParameterMarkers" }, { "buildPreparedStrings" }, { "insertCommand", "updateCommand", "deleteCommand", "insert", "update",
					"delete", "updateAsync", "insertAsync", "deleteAsync", "query", "command", "commandAsync", "query", "queryAsync" },
			{ "newOutputStream" }, CONSTRUCTOR };
}
