package org.brutusin.instrumentation.logging;

public interface IAgentConstants {

	String TRACE_REGEX = "(^java\\.lang.*)|(^org\\.brutusin.*)|(^com\\.microsoft\\.sqlserver.*)|(^com\\.mysql.*)|(^sun\\.reflect.*)|(^java\\.sql.*)|(com\\.mongodb.*)|(org\\.apache\\.commons.*)|(org\\.mongodb.*)";

	String[] COMPLETE_LIST = {
			"final com.mysql.jdbc.ResultSetInternalMethods com.mysql.jdbc.MysqlIO.sqlQueryDirect(com.mysql.jdbc.StatementImpl,java.lang.String,java.lang.String,com.mysql.jdbc.Buffer,int,int,int,boolean,java.lang.String,com.mysql.jdbc.Field[]) throws java.lang.Exception",
			"static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException",
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
			};

	String[] ALL_CLASSES = { "com/mysql/jdbc/MysqlIO", "java/lang/ProcessImpl",
			"com/microsoft/sqlserver/jdbc/SQLServerStatement", 
			"com/microsoft/sqlserver/jdbc/TDSWriter",
			"com/microsoft/sqlserver/jdbc/SQLServerConnection",
			"com/microsoft/sqlserver/jdbc/SQLServerPreparedStatement",
			"com/mongodb/connection/DefaultServerConnection"};

	String[] EXECUTORS = {
			"static java.lang.Process java.lang.ProcessImpl.start(java.lang.String[],java.util.Map<java.lang.String, java.lang.String>,java.lang.String,java.lang.ProcessBuilder$Redirect[],boolean) throws java.io.IOException",
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
			};
	
	String MSSQL_EXECUTOR = "final void com.microsoft.sqlserver.jdbc.SQLServerStatement.executeStatement(com.microsoft.sqlserver.jdbc.TDSCommand) throws com.microsoft.sqlserver.jdbc.SQLServerException";

	String[] CONSTRUCTOR = { "<init>" };

	String[][] ALL_METHODS = { { "sqlQueryDirect" }, { "start" }, 
			{ "executeStatement", "replaceMarkerWithNull" },
			{ "writeString" }, { "replaceParameterMarkers" }, { "buildPreparedStrings" },
			{ "insertCommand", "updateCommand", "deleteCommand", "insert", "update", "delete", "updateAsync",
					"insertAsync", "deleteAsync", "query", "command", "commandAsync", "query", "queryAsync" }};
}
