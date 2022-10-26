package com.k2cybersecurity.intcodeagent.logging;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public interface IAgentConstants {

    String CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT = "weblogic/servlet/internal/WebAppServletContext";

    String TRACE_REGEX = "^((?!(org\\.apache\\.jsp))((sun|java|javax|com\\.sun|jdk)|(org\\.apache|com\\.k2cybersecurity\\.intcodeagent|com\\.newrelic\\.|k2\\.io\\.org|com\\.microsoft\\.sqlserver|com\\.mysql|sun\\.reflect|org\\.hibernate|com\\.mongodb|org\\.apache\\.commons|org\\.mongodb|org\\.eclipse\\.jetty|net\\.sourceforge\\.eclipsejetty|org\\.springframework|org\\.slf4j|org\\.eclipse\\.jdt|com\\.opensymphony|k2\\.org\\.objectweb\\.asm|weblogic\\.|freemarker\\.cache|com\\.mchange|org\\.postgresql|oracle\\.jdbc|org\\.hsqldb|ch\\.qos\\.logback|io\\.micrometer|k2\\.org\\.json|k2\\.com\\.fasterxml|com\\.ibm|io\\.undertow|org\\.jboss|org\\.wildfly|org\\.glassfish|freemaker|org\\.thymeleaf|org\\.xnio|com\\.samskivert\\.mustache|org\\.codehaus|com\\.github\\.mustachejava|groovy|com\\.oracle|weblogic|org\\.primefaces|spark|org\\.mozilla|com.\\zaxxer)))\\..*";

    Pattern TRACE_SKIP_REGEX = Pattern.compile("^(sun|java|javax|com\\.sun|jdk)\\..*");

    List<String> ALLOWED_EXTENSIONS = Arrays.asList(new String[]{"css", "html", "htm", "jsp", "js", "classtmp"});

    List<String> SOURCE_EXENSIONS = Arrays.asList(new String[]{"class", "jsp", "jar", "java"});

    // HSQL
    String HSQL = "HSQL";
    String HSQL_DB_IDENTIFIER = "hsqldb.";
    String CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION = "org/hsqldb/HSQLClientConnection";
    String CLASS_ORG_HSQLDB_SESSION = "org/hsqldb/Session";
    String CLASS_ORG_HSQLDB_CLIENT_CONNECTION = "org/hsqldb/ClientConnection";

    // PSQL
    String POSTGRESQL = "POSTGRESQL";
    String POSTGRESQL_DB_IDENTIFIER = "postgresql.";
    String CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL = "org/postgresql/core/v2/QueryExecutorImpl";
    String CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL = "org/postgresql/core/v3/QueryExecutorImpl";

    //firebird
    String FIREBIRD = "FIREBIRD";
    String FIREBIRD_DB_IDENTIFIER = "firebirdsql.";

    //H2
    String H2 = "H2";
    String H2_DB_IDENTIFIER = "h2.";

    //Derby
    String DERBY = "DERBY";
    String DERBY_DB_IDENTIFIER = "derby.";

    //IBMDB2
    String IBMDB2 = "IBMDB2";
    String IBMDB2_DB_IDENTIFIER = "ibm.";

    //Teradata
    String TERADATA = "TERADATA";
    String TERADATA_DB_IDENTIFIER = "teradata.";

    //MariaDB
    String MARIADB = "MARIADB";
    String MARIADB_DB_IDENTIFIER = "mariadb.";

    String UNKNOWN = "UNKNOWN";

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
    String MONGO = "MONGO";
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

    // WSLiberty
    String COM_IBM_WS_GENERICBNF_INTERNAL_BNFHEADERSIMPL = "com/ibm/ws/genericbnf/internal/BNFHeadersImpl";
    String COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTPINBOUNDLINK = "com/ibm/ws/http/channel/internal/inbound/HttpInboundLink";

    // WAS Traditional
    String COM_IBM_WS_GENERICBNF_IMPL_BNFHEADERSIMPL = "com/ibm/ws/genericbnf/impl/BNFHeadersImpl";
    String COM_IBM_WS_HTTP_CHANNEL_INBOUND_IMPL_HTTPINBOUNDLINK = "com/ibm/ws/http/channel/inbound/impl/HttpInboundLink";

    // JBoss
    String IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER = "io/undertow/servlet/handlers/ServletHandler";

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

    String JAVA_IO_FILE_INPUTSTREAM_OPEN = "private void java.io.FileInputStream.open(java.lang.String) throws java.io.FileNotFoundException";
    String JAVA_IO_FILE_OUTPUTSTREAM_OPEN = "private void java.io.FileOutputStream.open(java.lang.String,boolean) throws java.io.FileNotFoundException";

    String SUN_NIO_FS_UNIX_PATH = "sun.nio.fs.UnixPath";
    String JAVA_NIO_UNIX_OPEN = "static int sun.nio.fs.UnixNativeDispatcher.open(sun.nio.fs.UnixPath,int,int) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_FOPEN = "static long sun.nio.fs.UnixNativeDispatcher.fopen(sun.nio.fs.UnixPath,java.lang.String) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_LINK = "static void sun.nio.fs.UnixNativeDispatcher.link(sun.nio.fs.UnixPath,sun.nio.fs.UnixPath) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_UNLINK = "static void sun.nio.fs.UnixNativeDispatcher.unlink(sun.nio.fs.UnixPath) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_MKNOD = "static void sun.nio.fs.UnixNativeDispatcher.mknod(sun.nio.fs.UnixPath,int,long) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_RENAME = "static void sun.nio.fs.UnixNativeDispatcher.rename(sun.nio.fs.UnixPath,sun.nio.fs.UnixPath) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_MKDIR = "static void sun.nio.fs.UnixNativeDispatcher.mkdir(sun.nio.fs.UnixPath,int) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_RMDIR = "static void sun.nio.fs.UnixNativeDispatcher.rmdir(sun.nio.fs.UnixPath) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_SYMLINK = "static void sun.nio.fs.UnixNativeDispatcher.symlink(byte[],sun.nio.fs.UnixPath) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_CHOWN = "static void sun.nio.fs.UnixNativeDispatcher.chown(sun.nio.fs.UnixPath,int,int) throws sun.nio.fs.UnixException";
    String JAVA_NIO_UNIX_CHMOD = "static void sun.nio.fs.UnixNativeDispatcher.chmod(sun.nio.fs.UnixPath,int) throws sun.nio.fs.UnixException";

    String JAVA_IO_UNIX_FS_DELETE = "public boolean java.io.UnixFileSystem.delete(java.io.File)";
    String JAVA_IO_RANDOM_ACCESS_FILE_OPEN = "private void java.io.RandomAccessFile.open(java.lang.String,int) throws java.io.FileNotFoundException";

    String CLASS_APACHE_COMMONS_HTTP_METHOD_DIRECTOR = "org/apache/commons/httpclient/HttpMethodDirector";
    String APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD = "private void org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(org.apache.commons.httpclient.HttpMethod) throws java.io.IOException,org.apache.commons.httpclient.HttpException";

    String CLASS_OKHTTP_HTTP_ENGINE = "com/squareup/okhttp/internal/http/HttpEngine";
    String OKHTTP_HTTP_ENGINE_METHOD = "public void com.squareup.okhttp.internal.http.HttpEngine.sendRequest() throws com.squareup.okhttp.internal.http.RequestException,com.squareup.okhttp.internal.http.RouteException,java.io.IOException";

    String CLASS_WEBLOGIC_HTTP_HANDLER = "weblogic/net/http/Handler";
    String WEBLOGIC_OPEN_CONNECTION_METHOD = "protected java.net.URLConnection weblogic.net.http.Handler.openConnection(java.net.URL,java.net.Proxy) throws java.io.IOException";

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

    // HSQL_DB v2.3.4
    String HSQL_V2_3_4_CLIENT_CONNECTION = "public synchronized org.hsqldb.result.Result org.hsqldb.ClientConnection.execute(org.hsqldb.result.Result)";

    String CLASS_JAVA_IO_FILE_OUTPUT_STREAM = "java/io/FileOutputStream";
    String CLASS_JAVA_IO_FILE_INPUT_STREAM = "java/io/FileInputStream";
    String CLASS_SUN_NIO_FS_UNIX_NATIVE_DISPATCHER = "sun/nio/fs/UnixNativeDispatcher";

    /**
     * Source Method Identifiers for argument resolution
     */
    String MSSQL = "MSSQL";
    String MSSQL_DB_IDENTIFIER = "sqlserver.";
    String MSSQL_IDENTIFIER = "com.microsoft.sqlserver";

    String MYSQL = "MYSQL";
    String MYSQL_DB_IDENTIFIER = "mysql.";
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

    /**
     * JBoss constants
     */
//	String JBOSS_WILDFLY_HTTP_REQUEST_PARSER_HANDLE = "public void io.undertow.server.protocol.http.HttpRequestParser.handle(java.nio.ByteBuffer,io.undertow.server.protocol.http.ParseState,io.undertow.server.HttpServerExchange) throws io.undertow.util.BadRequestException";
//	String JBOSS_WILDFLY_HTTP_REQUEST_PARSER_HANDLE_2 = "public void io.undertow.server.protocol.http.HttpRequestParser.handle(java.nio.ByteBuffer,io.undertow.server.protocol.http.ParseState,io.undertow.server.HttpServerExchange)";
    // String PUBLIC_VOID_ORG_JBOSS_THREADS_CONTEXT_CLASS_LOADER_SAVING_RUNNABLE_RUN
    // = "public void org.jboss.threads.ContextClassLoaderSavingRunnable.run()";
    String PUBLIC_VOID_IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER_HANDLE_REQUEST_IO_UNDERTOW_SERVER_HTTP_SERVER_EXCHANGE_THROWS_JAVA_IO_IO_EXCEPTION_JAVAX_SERVLET_SERVLET_EXCEPTION = "public void io.undertow.servlet.handlers.ServletHandler.handleRequest(io.undertow.server.HttpServerExchange) throws java.io.IOException,javax.servlet.ServletException";

    //	String PRIVATE_INT_ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR_TRY_EXECUTE_JAVA_LANG_RUNNABLE = "private int org.jboss.threads.EnhancedQueueExecutor.tryExecute(java.lang.Runnable)";
    String FIELD_NEXT = "next";
    String ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$Q_NODE = "org.jboss.threads.EnhancedQueueExecutor$QNode";
    //	String PUBLIC_JAVA_LANG_THREAD_ORG_XNIO_XNIO_WORKER$_WORKER_THREAD_FACTORY_NEW_THREAD_JAVA_LANG_RUNNABLE = "public java.lang.Thread org.xnio.XnioWorker$WorkerThreadFactory.newThread(java.lang.Runnable)";
    String FIELD_GET = "get";
    String JAVA_NIO_DIRECT_BYTE_BUFFER = "java.nio.DirectByteBuffer";
    String FIELD_LIMIT = "limit";
    String JAVA_NIO_BUFFER = "java.nio.Buffer";
    String FIELD_THREAD = "thread";
    String ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$_POOL_THREAD_NODE = "org.jboss.threads.EnhancedQueueExecutor$PoolThreadNode";
    String ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$_TASK_NODE = "org.jboss.threads.EnhancedQueueExecutor$TaskNode";
    String ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR = "org.jboss.threads.EnhancedQueueExecutor";
    String TAIL = "tail";
    String FIRST_WAITER = "firstWaiter";
    String NOT_EMPTY = "notEmpty";
    String TASK_QUEUE = "taskQueue";
//	String ORG_XNIO_XNIO_WORKER = "org.xnio.XnioWorker";
//	String PUBLIC_VOID_ORG_XNIO_XNIO_WORKER_EXECUTE_JAVA_LANG_RUNNABLE = "public void org.xnio.XnioWorker.execute(java.lang.Runnable)";

    String WEBLOGIC_INVOKE_SERVLET = "public java.lang.Throwable weblogic.servlet.internal.StubSecurityHelper.invokeServlet(javax.servlet.ServletRequest,javax.servlet.http.HttpServletRequest,weblogic.servlet.internal.ServletRequestImpl,javax.servlet.ServletResponse,javax.servlet.http.HttpServletResponse,javax.servlet.Servlet) throws javax.servlet.ServletException";

    String WEBLOGIC_SERVLET_EXECUTE = "void weblogic.servlet.internal.WebAppServletContext.execute(weblogic.servlet.internal.ServletRequestImpl,weblogic.servlet.internal.ServletResponseImpl) throws java.io.IOException";

    /**
     * MSSQL FIELD CONSTANTS
     */
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

    /**
     * MSSQL CLASS CONSTANTS
     */
    String MSSQL_SERVER_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement";
    String MSSQL_PREPARED_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement";
    String MSSQL_PREPARED_BATCH_STATEMENT_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement.PrepStmtBatchExecCmd";
    String MSSQL_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtExecCmd";
    String MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS = "com.microsoft.sqlserver.jdbc.SQLServerStatement.StmtBatchExecCmd";

    /**
     * MySQL CLASS CONSTANTS
     */
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

    /**
     * Mongo constants
     */

    String MONGO_NAMESPACE_FIELD = "namespace";
    String MONGO_COMMAND_FIELD = "command";
    String MONGO_PAYLOAD_FIELD = "payload";
    String MONGO_DELETE_REQUEST_FIELD = "deleteRequests";
    String MOGNO_ELEMENT_DATA_FIELD = "elementData";
    String MONGO_FILTER_FIELD = "filter";
    String MONGO_MULTIPLE_UPDATES_FIELD = "updates";
    String MONGO_SINGLE_UPDATE_FIELD = "update";
    String MONGO_INSERT_REQUESTS_FIELD = "insertRequests";
    String MONGO_INSERT_REQUEST_LIST_FIELD = "insertRequestList";
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

    String BSONDOCUMENT = "BsonDocument";
    String DELETES = "deletes";
    String QUERY_DOCUMENT = "queryDocument";

    /**
     * Oracle DB constants
     */
    String ORACLE = "ORACLE";
    String ORACLE_DB_IDENTIFIER = "oracle.jdbc.";
    String ORACLE_IDENTIFIER = "oracle.jdbc.driver";
    String ORACLE_CONNECTION_IDENTIFIER = "oracle.jdbc.driver.T4C8Oall";
    String ORACLE_STATEMENT_CLASS_IDENTIFIER = "oracle.jdbc.driver.OracleStatement";

    /**
     * Http constants
     **/

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

    String SOURCESTRING = "sourceString";
    String EXECUTIONID = "executionId";
    String STARTTIME = "startTime";
    String FILEINTEGRITYBEAN = "FileIntegrityBean";
    String PARAMETERS = "parameters";
    String QUERY = "query";
    String FILTER = "filter";
    String NAME = "name";
    String COMMAND = "command";
    String FIELDS = "fields";
    String DOT_JAVA_COLON = ".java:";
    String URL = "url";
    String GET_REQUEST = "getRequest";
    char QUESTION_MARK = '?';
    String URI = "uri";
    String REQUEST = "request";
    String JDK_INCUBATOR_HTTP_MULTI_EXCHANGE = "jdk.incubator.http.MultiExchange";
    String SETUP_CURRENT_ENTITY = "setupCurrentEntity";
    String XML_ENTITY_MANAGER = "XMLEntityManager";
    String SCAN_DOCUMENT = "scanDocument";
    String XML_DOCUMENT_FRAGMENT_SCANNER_IMPL = "XMLDocumentFragmentScannerImpl";
    String UNCHECKED = "unchecked";
    String UNUSED = "unused";
    String PROC_S_EXE = "/proc/%s/exe";
    String PROC_S_COMM = "/proc/%s/comm";
    String STATIC = "STATIC";
    String DYNAMIC = "DYNAMIC";

    //Loggers
    String PRINTING_STACK_TRACE_FOR_RCI_EVENT_S_S = "Printing stack trace for rci event : %s : %s";
    String PRINTING_STACK_TRACE_FOR_PROBABLE_RCI_EVENT_S_S = "Printing stack trace for probable rci event : %s : %s";
    String PRINTING_STACK_TRACE_FOR_DESERIALISE_EVENT_S_S = "Printing stack trace for deserialise event : %s : %s";
    String PRINTING_STACK_TRACE_FOR_XXE_EVENT_S_S = "Printing stack trace for xxe event : %s : %s";
    String ERROR_IN_PARTIAL_SSRF_VALIDATOR = "Error in partialSSRFValidator : ";
    String ERROR_IN_GENERATE_EVENT_WHILE_CREATING_INT_CODE_RESULT_BEAN = "Error in generateEvent while creating IntCodeResultBean: ";
    String DROPPING_EVENT = "Dropping event ";
    String ERROR_IN_GENERATE_EVENT_WHILE_CREATING_JAVA_AGENT_DYNAMIC_PATH_BEAN = "Error in generateEvent while creating JavaAgentDynamicPathBean: ";
    String DUE_TO_BUFFER_CAPACITY_REACHED = " due to buffer capacity reached";
    String DROPPING_DYNAMIC_JAR_PATH_BEAN_EVENT = "Dropping dynamicJarPathBean event ";
    String ERROR_IN_GET_PSQL_PARAMETER_VALUE = "Error in getPSQLParameterValue: ";
    String ERROR_IN_GET_HSQL_PARAMETER_VALUE_FOR_HSQL_V1_8_V2_3_4 = "Error in getHSQLParameterValue for HSQL_V1_8/V2_3_4: ";
    String ERROR_IN_GET_HSQL_PARAMETER_VALUE_FOR_HSQL_V2_4 = "Error in getHSQLParameterValue for HSQL_V2_4: ";
    String ERROR_IN_GET_OK_HTTP_REQUEST_PARAMETERS = "Error in getOkHttpRequestParameters : ";
    String ERROR_IN_GET_APACHE_COMMONS_HTTP_REQUEST_PARAMETERS = "Error in getApacheCommonsHttpRequestParameters : ";
    String ERROR_IN_GET_APACHE_HTTP_REQUEST_PARAMETERS = "Error in getApacheHttpRequestParameters : ";
    String ERROR_IN_GET_JAVA9_HTTP_CLIENT_PARAMETERS = "Error in getJava9HttpClientParameters : ";
    String ERROR_IN_TO_STRING = "Error in toString: ";
    String ERROR_IN_GET_ORACLE_PARAMETER_VALUE = "Error in getOracleParameterValue: ";
    String ERROR_IN_GET_MY_SQL_PARAMETER_VALUE = "Error in getMySQLParameterValue: ";
    String EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN = "Exception occured in createApplicationInfoBean: ";
    String EXCEPTION_OCCURED_IN_EVENT_SEND_POOL = "Exception occured in EventSendPool: ";
    String ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET = "Error occured while trying to connect to wsocket: ";
    String ERROR_WHILE_INITIALISING_THE_K2_AGENT = "Error while initialising the K2 Agent :";

    // IPScheduledThread.java file constants
    String HOST_IP_PROPERTIES_FILE = "/opt/k2-ic/hostip.properties";

    String HCSCHEDULEDTHREAD_ = "K2-hcScheduledThread-";
    String WSRECONNECTSCHEDULEDTHREAD_ = "K2-WSReconnect-";

    String ACK_MSG = "ACK";
    // EventThreadPool.java file constants

    String K2_JAVA_AGENT = "K2-Java-Agent-";
    String K2_LISTERNER = "K2-ControlCommand-Listener-";

    // LoggingInterceptor Constants
    char DIR_SEPERATOR = '/';
    String CGROUP_FILE_NAME = "/proc/self/cgroup";
    String DOCKER_DIR = "docker/";
    String ECS_DIR = "ecs/";
    String KUBEPODS_DIR = "kubepods/";
    String KUBEPODS_SLICE_DIR = "kubepods.slice/";
    String LXC_DIR = "lxc/";
    String JAR_PATH_INIT_MSG = "Pooling getJarPathResultExecutorService to fetch results.";
    String JAR_PATH_FETCH_SUCCESS_MSG = "getJarPathResultExecutorService result fetched successfully.";
    String JAR_PATH_EMPTY_RESULT_ERR = "getJarPathResultExecutorService result is empty.";
    String JAR_PATH_TIMEOUT_ERR = "Timeout reached waiting for getJarPathResultExecutorService.";
    String HOST_PROP_FILE_NAME = "/opt/k2-ic/hostip.properties";
    String HOST_IP_FOUND_MSG = "hostip found: ";
    String JA_CONNECT_SUCCESS_MSG = "K2-JavaAgent installed successfully.";
    String PROC_DIR = "/proc/";
    String PROC_SELF_DIR = "/proc/self";
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

    String JSON_NAME_APPLICATION_INFO_BEAN = "applicationinfo";
    String JSON_NAME_INTCODE_RESULT_BEAN = "Event";
    String JSON_NAME_HEALTHCHECK = "LAhealthcheck";
    String JSON_NAME_DYNAMICJARPATH_BEAN = "dynamicjarpath";
    String JSON_NAME_SHUTDOWN = "shutdown";
    String JSON_NAME_FUZZ_FAIL = "fuzzfail";
    String JSON_NAME_HTTP_CONNECTION_STAT = "http-connection-stat";
    String JSON_NAME_EXIT_EVENT = "exit-event";



    String FIELD_SOCKET_CHANNEL = "socketChannel";
    String ORG_XNIO_NIO_NIO_SOCKET_CONDUIT = "org.xnio.nio.NioSocketConduit";
    String FIELD_ORIGINAL_SOURCE_CONDUIT = "originalSourceConduit";
    String FIELD_CONNECTION = "connection";
    String METHOD_GET_REMOTE_HOST_ADDRESS = "getRemoteHostAddress";
    String METHOD_GET_CONNECTION_DESCRIPTOR = "getConnectionDescriptor";
    String METHOD_GET_VIRTUAL_CONNECTION = "getVirtualConnection";
    String COM_IBM_WSSPI_CHANNELFW_CONNECTION_DESCRIPTOR = "com.ibm.wsspi.channelfw.ConnectionDescriptor";
    String COM_IBM_WSSPI_CHANNELFW_VIRTUAL_CONNECTION = "com.ibm.wsspi.channelfw.VirtualConnection";
    String COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTP_INBOUND_LINK = "com.ibm.ws.http.channel.internal.inbound.HttpInboundLink";
    String COM_IBM_WS_HTTP_CHANNEL_INBOUND_HTTP_INBOUND_LINK = "com.ibm.ws.http.channel.inbound.impl.HttpInboundLink";

    String INVOKE_0 = "invoke0";
    String READ_OBJECT = "readObject";
    String REFLECT_NATIVE_METHOD_ACCESSOR_IMPL = "reflect.NativeMethodAccessorImpl";
    String INVOKE = "invoke";
    String JAVA_IO_UNIX_FILE_SYSTEM = "java/io/UnixFileSystem";
    String JAVA_IO_RANDOM_ACCESS_FILE = "java/io/RandomAccessFile";
    String INTERCEPTED_HTTP_REQUEST = "Intercepted HTTP request :: %s :: %s";

    String GET_DATA = "getData";
    String GET_SIZE = "getSize";
    String GET_NAVIGATOR = "getNavigator";
    String MAIN_STRING = "mainString";
    // CRYPTO Constants
    String CIPHER = "CIPHER";
    String JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING = "public static final javax.crypto.Cipher javax.crypto.Cipher.getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException,javax.crypto.NoSuchPaddingException";
    String JAVAX_CRYPTO_CIPHER_GETINSTANCE_STRING_PROVIDER = "public static final javax.crypto.Cipher javax.crypto.Cipher.getInstance(java.lang.String,java.security.Provider) throws java.security.NoSuchAlgorithmException,javax.crypto.NoSuchPaddingException";

    String KEYGENERATOR = "KEYGENERATOR";
    String JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING = "public static final javax.crypto.KeyGenerator javax.crypto.KeyGenerator.getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException";
    String JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_STRING = "public static final javax.crypto.KeyGenerator javax.crypto.KeyGenerator.getInstance(java.lang.String,java.lang.String) throws java.security.NoSuchAlgorithmException,java.security.NoSuchProviderException";
    String JAVAX_CRYPTO_KEYGENERATOR_GETINSTANCE_STRING_PROVIDER = "public static final javax.crypto.KeyGenerator javax.crypto.KeyGenerator.getInstance(java.lang.String,java.security.Provider) throws java.security.NoSuchAlgorithmException";

    String KEYPAIRGENERATOR = "KEYPAIRGENERATOR";
    String JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING = "public static java.security.KeyPairGenerator java.security.KeyPairGenerator.getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException";
    String JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_STRING = "public static java.security.KeyPairGenerator java.security.KeyPairGenerator.getInstance(java.lang.String,java.lang.String) throws java.security.NoSuchAlgorithmException,java.security.NoSuchProviderException";
    String JAVA_SECURITY_KEYPAIRGENERATOR_GETINSTANCE_STRING_PROVIDER = "public static java.security.KeyPairGenerator java.security.KeyPairGenerator.getInstance(java.lang.String,java.security.Provider) throws java.security.NoSuchAlgorithmException";

    // HASH Constants
    String JAVA_SECURITY_MESSAGEDIGEST_GETINSTANCE_STRING = "public static java.security.MessageDigest java.security.MessageDigest.getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException";
    String JAVA_SECURITY_MESSAGEDIGEST_GETINSTANCE_STRING_STRING = "public static java.security.MessageDigest java.security.MessageDigest.getInstance(java.lang.String,java.lang.String) throws java.security.NoSuchAlgorithmException,java.security.NoSuchProviderException";
    String JAVA_SECURITY_MESSAGEDIGEST_GETINSTANCE_STRING_PROVIDER = "public static java.security.MessageDigest java.security.MessageDigest.getInstance(java.lang.String,java.security.Provider) throws java.security.NoSuchAlgorithmException";
    String BLOCKING_END_TIME = "blockingEndTime";
    String ERROR_WHILE_DETERMINING_HOSTIP_FROM_DEFAULT_GATEWAY = "Error while determining hostip from default gateway";

    String K2_FUZZ_REQUEST_ID = "k2-fuzz-request-id";
    String INIT = "<init>";
    String SUN_REFLECT = "sun.reflect.";
    String COM_SUN = "com.sun.";
    String UNABLE_TO_GET_AGENT_STARTUP_INFOARMATION = "Unable to get Agent startup information due to error:";

    String K2_API_CALLER = "K2-API-CALLER";
    String K2_TRACING_HEADER = "K2-TRACING-DATA";

    String LINUX = "linux";
    String WINDOWS = "windows";
    String MAC = "mac";
    String K_2_FUZZ_REQUEST_ID = "k2-fuzz-request-id";

    String EXCEPTION_OCCURRED_IN_CREATE_APPLICATION_INFO_BEAN = "Exception occurred in createApplicationInfoBean: ";
    String EXCEPTION_OCCURRED_IN_EVENT_SEND_POOL = "Exception occurred in EventSendPool: ";
    String ERROR_OCCURRED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET = "Error occurred while trying to connect to web-socket: ";

    String APPLICATION_INFO_SENT_ON_WS_CONNECT = "[STEP-3][COMPLETE][APP_INFO] Application info sent to Prevent-Web service : %s";
    String SENDING_APPLICATION_INFO_ON_WS_CONNECT = "[APP_INFO] Sending application info to Prevent-Web service : %s";
    String WS_CONNECTION_SUCCESSFUL = "[STEP-4][COMPLETE][WS] Connected to Prevent-Web service at %s.";
    String WS_CONNECTION_UNSUCCESSFUL = "[WS] Error connecting to Prevent-Web service at %s :";
    String INIT_WS_CONNECTION = "[STEP-4][BEGIN][WS] Connecting to Prevent-Web service at %s.";


    String RECEIVED_AGENT_POLICY = "[STEP-7][BEGIN][POLICY] Received policy data from Prevent-Web service : %s";
    String UNABLE_TO_PARSE_AGENT_POLICY_DUE_TO_ERROR = "[POLICY] Error while parsing policy data from Prevent-Web service : %s : %s";
    String UNABLE_TO_VALIDATE_AGENT_POLICY_DUE_TO_ERROR = "[POLICY] Error while validating policy data from Prevent-Web service : %s : ";
    String UNABLE_TO_VALIDATE_AGENT_POLICY_PARAMETER_DUE_TO_ERROR = "[POLICY] Error while validating policy parameters data from Prevent-Web service : %s : ";

    String UNABLE_TO_VALIDATE_AGENT_POLICY_DUE_TO_ERROR_FILE = "[POLICY] Error while validating policy data from local policy file change. Falling back to current : %s : ";
    String UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR = "[POLICY] Error while applying policy : %s :";
    String AGENT_POLICY_APPLIED_S = "[STEP-7][COMPLETE][POLICY] Policy applied : : %s";
    String AGENT_POLICY_PARAM_APPLIED_S = "[POLICY] Agent Policy parameters applied : %s";
    String UNABLE_TO_SET_AGENT_POLICY_PARAM_DUE_TO_ERROR = "[POLICY] Unable to set Agent Policy Parameters due to error:";

    String STARTING_MODULE_LOG = "[BEGIN][MODULE] Starting %s.";
    String ERROR_STARTING_MODULE_LOG = "[MODULE] Error while starting %s :L ";
    String STARTED_MODULE_LOG = "[COMPLETE][MODULE] Started %s.";

    String AGENT_INIT_LOG_STEP_FIVE = "[STEP-5][BEGIN][MODULE] Start Threads/pools/scheduler.";
    String AGENT_INIT_LOG_STEP_FIVE_END = "[STEP-5][COMPLETE][MODULE] Started Threads/pools/scheduler.";
    int NUMBER_OF_RETRIES = 7;
    String POLICY_NO_CHANGE_IN_GLOBAL_POLICY_PARAMETERS_RESPONSE_BODY = "[POLICY] No change in global policy parameters response : %s : body: %s";
    String POLICY_GLOBAL_POLICY_PARAMETERS_API_FAILURE_RESPONSE_BODY = "[POLICY] API global policy parameters failure!!! response : %s : body: %s";
    String POLICY_VERSION_CHANGED_POLICY_PARAMETER_PULL_REQUIRED_RESPONSE_BODY = "[POLICY] Version changed policy parameter pull required response : %s : body: %s";
    String POLICY_PARAMETER_VERSION_CHECK_FAILED_MESSAGE_CAUSE = "Policy parameter version check failed MESSAGE: %s CAUSE: %s";


    String DEFAULT_K2HOME_LINUX = "/opt/k2root";
    String DEFAULT_K2HOME_WIN = "C:\\Users\\Public\\K2\\k2root";
    String POLICY_PULL_RESPONSE_IS_NULL = "Policy pull response is null!!!";
    String VULNERABLE = "VULNERABLE";
    String TERMINATING = "Terminating";
    String SHUTTING_DOWN_WITH_STATUS = "Shutting down with status: ";

    String STATUS_FILE_TEMPLATE = "Snapshot taken at: ${timestamp}\n" +
            "K2 Java Agent started at: ${start-time} with application uuid: ${application-uuid}\n" +
            "K2HOME is: ${k2-home}, permissions read & write: ${k2-home-permissions}\n" +
            "Loading Agent from ${agent-location}\n" +
            "Using K2 for JAVA, Java version: ${java-version}, PID:${pid}\n" +
            "Application was invoked as: ${java-binary}\n" +
            "Current working directory: ${cwd}, permissions read & write: ${cwd-permissions}\n" +
            "Agent is running in mode: ${group-name}\n" +
            "Application server: ${server-name}\n" +
            "Framework detected: ${framework}\n" +
            "Established websocket connection to Prevent Web: ${validator-url}, Status: ${validator-server-status}\n" +
            "Instrumentation successful\n" +
            "Policy applied successfully. Policy version is: ${policy-version}\n" +
            "Started Inbound and Outbound HTTP request monitoring \n" +
            "\n" +
            "Process stats: \n" +
            "${latest-process-stats}\n" +
            "\n" +
            "Service stats: \n" +
            "${latest-service-stats}\n" +
            "\n" +
            "Last 5 errors:\n" +
            "${last-5-errors}\n" +
            "\n" +
            "Last 5 Heath Checks:\n" +
            "${last-5-hc}";
}