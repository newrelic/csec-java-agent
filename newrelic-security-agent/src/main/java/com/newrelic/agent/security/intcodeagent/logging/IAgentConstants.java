package com.newrelic.agent.security.intcodeagent.logging;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public interface IAgentConstants {


    String TRACE_REGEX = "^((?!(org\\.apache\\.jsp))((sun|java|javax|com\\.sun|jdk)|(org\\.apache|com\\.k2cybersecurity\\.intcodeagent|com\\.newrelic\\.|k2\\.io\\.org|com\\.microsoft\\.sqlserver|com\\.mysql|sun\\.reflect|org\\.hibernate|com\\.mongodb|org\\.apache\\.commons|org\\.mongodb|org\\.eclipse\\.jetty|net\\.sourceforge\\.eclipsejetty|org\\.springframework|org\\.slf4j|org\\.eclipse\\.jdt|com\\.opensymphony|k2\\.org\\.objectweb\\.asm|weblogic\\.|freemarker\\.cache|com\\.mchange|org\\.postgresql|oracle\\.jdbc|org\\.hsqldb|ch\\.qos\\.logback|io\\.micrometer|k2\\.org\\.json|k2\\.com\\.fasterxml|com\\.ibm|io\\.undertow|org\\.jboss|org\\.wildfly|org\\.glassfish|freemaker|org\\.thymeleaf|org\\.xnio|com\\.samskivert\\.mustache|org\\.codehaus|com\\.github\\.mustachejava|groovy|com\\.oracle|weblogic|org\\.primefaces|spark|org\\.mozilla|com.\\zaxxer)))\\..*";

    // MONGO
    String MONGO = "MONGO";

    String EXEC_URL_CLASS_LOADER_NEW_INSTANCE = "public static java.net.URLClassLoader java.net.URLClassLoader.newInstance(java.net.URL[])";

    String URL_CLASS_LOADER = "public java.net.URLClassLoader(java.net.URL[])";

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

    String JAVA_IO_FILE_INPUTSTREAM_OPEN = "private void java.io.FileInputStream.open(java.lang.String) throws java.io.FileNotFoundException";

    String PARAMETERS = "parameters";
    String QUERY = "query";
    String FILTER = "filter";
    String NAME = "name";

    String SETUP_CURRENT_ENTITY = "setupCurrentEntity";
    String XML_ENTITY_MANAGER = "XMLEntityManager";
    String SCAN_DOCUMENT = "scanDocument";
    String XML_DOCUMENT_FRAGMENT_SCANNER_IMPL = "XMLDocumentFragmentScannerImpl";
    String PROC_S_EXE = "/proc/%s/exe";
    String PROC_S_COMM = "/proc/%s/comm";
    String STATIC = "STATIC";

    String EXCEPTION_OCCURED_IN_CREATE_APPLICATION_INFO_BEAN = "Exception occured in createApplicationInfoBean: ";

    String SCHEDULEDTHREAD_ = "NR-CSEC-ScheduledThread-";

    String WSRECONNECTSCHEDULEDTHREAD_ = "NR-CSEC-WSReconnect-";


    String K2_JAVA_AGENT = "NR-CSEC-Java-Agent-";
    String K2_LISTERNER = "NR-CSEC-ControlCommand-Listener-";

    // LoggingInterceptor Constants
    char DIR_SEPERATOR = '/';
    String CGROUP_FILE_NAME = "/proc/self/cgroup";
    String DOCKER_DIR = "docker/";
    String ECS_DIR = "ecs/";
    String KUBEPODS_DIR = "kubepods/";
    String KUBEPODS_SLICE_DIR = "kubepods.slice/";
    String LXC_DIR = "lxc/";
    String PROC_DIR = "/proc/";
    String PROC_SELF_DIR = "/proc/self";
    String CMD_LINE_DIR = "/cmdline";
    String STAT = "/stat";
    char VMPID_SPLIT_CHAR = '@';

    String JSON_NAME_APPLICATION_INFO_BEAN = "applicationinfo";
    String JSON_NAME_INTCODE_RESULT_BEAN = "Event";
    String JSON_NAME_HEALTHCHECK = "LAhealthcheck";
    String JSON_NAME_DYNAMICJARPATH_BEAN = "dynamicjarpath";
    String JSON_NAME_SHUTDOWN = "shutdown";
    String JSON_NAME_FUZZ_FAIL = "fuzzfail";
    String JSON_NAME_HTTP_CONNECTION_STAT = "http-connection-stat";
    String JSON_NAME_EXIT_EVENT = "exit-event";

    String JSON_SEC_APPLICATION_URL_MAPPING = "sec-application-url-mapping";


    String INVOKE_0 = "invoke0";
    String READ_OBJECT = "readObject";
    String REFLECT_NATIVE_METHOD_ACCESSOR_IMPL = "reflect.NativeMethodAccessorImpl";
    String BLOCKING_END_TIME = "blockingEndTime";

    String SUN_REFLECT = "sun.reflect.";
    String COM_SUN = "com.sun.";

    String LINUX = "linux";
    String WINDOWS = "windows";
    String MAC = "mac";

    String APPLICATION_INFO_SENT_ON_WS_CONNECT = "[STEP-3][COMPLETE][APP_INFO] Application info sent to Security Engine : %s";
    String SENDING_APPLICATION_INFO_ON_WS_CONNECT = "[APP_INFO] Sending application info to Security Engine : %s";
    String WS_CONNECTION_UNSUCCESSFUL = "[WS] Error connecting to Security Engine at %s :";
    String WS_CONNECTION_UNSUCCESSFUL_INFO = "[WS] Error connecting to Security Engine at %s : %s : %s";

    String INIT_WS_CONNECTION = "[STEP-4] =>Web socket connection to SaaS validator established successfully at %s.";


    String RECEIVED_AGENT_POLICY = "[STEP-7][POLICY] Received policy data from Security Engine : %s";
    String UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR = "[POLICY] Error while applying policy : %s :";
    String AGENT_POLICY_APPLIED_S = "[STEP-7] => Received and applied policy/configuration : %s";
    String AGENT_POLICY_PARAM_APPLIED_S = "[POLICY] Agent Policy parameters applied : %s";
    String UNABLE_TO_SET_AGENT_POLICY_PARAM_DUE_TO_ERROR = "[POLICY] Unable to set Agent Policy Parameters due to error:";

    String STARTED_MODULE_LOG = "[COMPLETE][MODULE] Started %s.";
    String AGENT_INIT_LOG_STEP_FIVE_END = "[STEP-5] => Security agent components started";

    String VULNERABLE = "VULNERABLE";
    String TERMINATING = "Terminating";
    String SHUTTING_DOWN_WITH_STATUS = "Shutting down with status: ";

    String PROCESS_BINARY = "process-binary";

    String NR_APM_TRACE_ID = "trace.id";
    String NR_APM_SPAN_ID = "span.id";

}