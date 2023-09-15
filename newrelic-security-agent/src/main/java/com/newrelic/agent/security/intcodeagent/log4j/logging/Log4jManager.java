package com.newrelic.agent.security.intcodeagent.log4j.logging;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.*;
import org.apache.logging.log4j.core.config.*;
import org.apache.logging.log4j.core.config.builder.api.*;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class Log4jManager {

    public static final String LOG4J2_CONFIGURATION_FACTORY = "log4j2.configurationFactory";
    private final Logger logger;
    public boolean isLoggingToStdOut;

    private static final String CONSOLE_APPENDER_NAME = "Console";

    private static final String CONFIG_FILE_PROP = "log4j2.configurationFile";
    private static final String LEGACY_CONFIG_FILE_PROP = "log4j.configurationFile";
    private static final String CONTEXT_FACTORY_PROP = "log4j2.loggerContextFactory";

    private static final String CONTEXT_FACTORY_LOG4J_PROP = "org_apache_logging.log4j.contextFactory";

    private static final String AGENT_JAR_LOG4J_CONFIG_FILE = "/META-INF/logging/log4j2.xml";

    private Map<String, String> oldProperties = new HashMap<>();

    /**
     * The pattern to use for log messages.
     */
    static final String CONVERSION_PATTERN = "%d{ISO8601_OFFSET_DATE_TIME_HHMM} [%pid %tid] %logger %marker: %m%n";

    public static Log4jManager getInstance() {
        return InstanceHolder.instance;
    }

    public class SecurityConfigurationFactory extends ConfigurationFactory {

        @Override
        public String[] getSupportedTypes() {
            return new String[] { "*" };
        }

        @Override
        public Configuration getConfiguration(LoggerContext loggerContext, ConfigurationSource source) {
            ConfigurationBuilder<BuiltConfiguration> builder
                    = ConfigurationBuilderFactory.newConfigurationBuilder();
            AppenderComponentBuilder console = builder.newAppender("stdout", "Console");
            builder.add(console);

            AppenderComponentBuilder file = builder.newAppender("log", "File");
            file.addAttribute("fileName", LogFileHelper.getLogFileName());
            builder.add(file);

//        AppenderComponentBuilder rollingFile = builder.newAppender("rolling", "RollingFile");
//        rollingFile.addAttribute("fileName", "rolling.log");
//        rollingFile.addAttribute("filePattern", "rolling-%d{MM-dd-yy}.log.gz");
//
//        builder.add(rollingFile);

            FilterComponentBuilder flow = builder.newFilter(
                    "MarkerFilter",
                    Filter.Result.ACCEPT,
                    Filter.Result.DENY);
            flow.addAttribute("marker", "FLOW");

            console.add(flow);

            LayoutComponentBuilder standard
                    = builder.newLayout("PatternLayout");
            standard.addAttribute("pattern", "%d [%t] %-5level: %msg%n%throwable");

            console.add(standard);
            file.add(standard);

            RootLoggerComponentBuilder rootLogger
                    = builder.newRootLogger(Level.INFO);
            rootLogger.add(builder.newAppenderRef("stdout"));
            builder.add(rootLogger);
            return builder.build();
        }
    }

    private static final class InstanceHolder {
        static final Log4jManager instance = new Log4jManager();
    }


    private void configure(){


//        Configurator.initialize(builder.build());

    }

    private Log4jManager() {
        setProperties();
//        configure();
        logger = LogManager.getLogger();
        logger.info("test log");
        removeProperties();
    }

//    private Log4jManager() {
//        setProperties();
//        createRootLogger();
//        System.out.println("root logger created");
//        logger = LogManager.getLogger(Log4jManager.class);
//        String logFileName = LogFileHelper.getLogFileName();
////        int limit = NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_LIMIT, LogFileHelper.DEFAULT_LOG_LIMIT) * 1024;
//        int limit = 1000 * 1024;
//        int fileCount = Math.max(1, NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_COUNT, LogFileHelper.DEFAULT_LOG_FILE_COUNT));
//        boolean isDaily = NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_DAILY, LogFileHelper.DEFAULT_LOG_DAILY);
//        System.out.println(String.format("log file name %s , limit %sBytes, fileCount %s, isDaily %s", logFileName, limit, fileCount, isDaily));
//        setLoggingToStdOut();
//        System.out.println("log to stdout "+ isLoggingToStdOut);
//        if(isLoggingToStdOut){
//            addConsoleAppender();
//        } else {
//            configureFileAppender(logger.getName(), logFileName, limit, fileCount, isDaily);
//        }
//        removeProperties();
//        System.out.println("logger created");
//        logger.info("Logger created and working!!!!");
//    }

    private void configureFileAppender(String loggerName, String fileName, long logLimitBytes, int fileCount, boolean isDaily){
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        LoggerConfig loggerConfig = config.getLoggerConfig(loggerName);

        FileAppenderFactory fileAppenderFactory = new FileAppenderFactory(fileCount, logLimitBytes, fileName, isDaily);
        AbstractOutputStreamAppender<? extends FileManager> fileAppender = fileAppenderFactory.build();
        if (fileAppender == null) {
            return;
        }

        fileAppender.start();
        loggerConfig.addAppender(fileAppender, null, null);
        ctx.updateLoggers();
    }

    private void createRootLogger(){
        System.out.println("CONFIG_FILE_PROP " +System.getProperty(CONFIG_FILE_PROP));
        System.out.println("LEGACY_CONFIG_FILE_PROP " + System.getProperty(LEGACY_CONFIG_FILE_PROP));
        System.out.println("CONTEXT_FACTORY_PROP " + System.getProperty(CONTEXT_FACTORY_PROP));
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        LoggerConfig rootLoggerConfig = LoggerConfig.createLogger(false, Level.INFO,
                "com.newrelic", "true", new AppenderRef[0],
                null, config, null);
        config.addLogger("root", rootLoggerConfig);
        ctx.updateLoggers();
    }

    private void removeProperties() {
        restoreOldProperties(LOG4J2_CONFIGURATION_FACTORY);
        restoreOldProperties(CONTEXT_FACTORY_PROP);
    }

    private void setProperties() {
//        try {
//            URL log4jConfigXmlUrl;
//            if (Agent.getAgentJarURL().getFile().endsWith(".jar")) {
//                log4jConfigXmlUrl = new URL(new StringBuilder("jar:file:")
//                        .append(Agent.getAgentJarURL())
//                        .append("!")
//                        .append(AGENT_JAR_LOG4J_CONFIG_FILE)
//                        .toString());
//            } else {
//                log4jConfigXmlUrl = Agent.getAgentJarURL().toURI().toURL();
//            }
//            System.setProperty(CONFIG_FILE_PROP, log4jConfigXmlUrl.toString());
//            System.setProperty(LEGACY_CONFIG_FILE_PROP, log4jConfigXmlUrl.toString());
//             Log4j won't be able to find log4j-provider.properties because it isn't on the classpath (it's in our agent) so this sets it manually
//
//        } catch (URISyntaxException | MalformedURLException e) {
//        }
        saveOldProperties(CONTEXT_FACTORY_PROP, "org.apache.logging.log4j.core.impl.Log4jContextFactory");
        saveOldProperties(LOG4J2_CONFIGURATION_FACTORY, "com.newrelic.agent.security.intcodeagent.log4j.logging.Log4jManager.SecurityConfigurationFactory");
//        System.setProperty(StringUtils.replace(CONTEXT_FACTORY_LOG4J_PROP, "_","."), "org.apache.logging.log4j.core.impl.Log4jContextFactory");
    }

    private void saveOldProperties(String key, String value) {
        String oldValue = System.getProperties().getProperty(key);
        if(StringUtils.isNotBlank(oldValue)){
            oldProperties.put(key, oldValue);
        }
        System.setProperty(key, value);

    }

    private void restoreOldProperties(String key) {
        if(oldProperties.containsKey(key)){
            System.setProperty(key, oldProperties.get(key));
        }
        System.getProperties().remove(key);
    }

    public boolean isLoggingToStdOut() {
        return isLoggingToStdOut;
    }

    public void addConsoleAppender() {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        LoggerConfig loggerConfig = config.getLoggerConfig(logger.getName());

        if (loggerConfig.getAppenders().get(CONSOLE_APPENDER_NAME) != null) {
            return;
        }

        ConsoleAppender consoleAppender = ((ConsoleAppender.Builder) ConsoleAppender.newBuilder()
                .setTarget(ConsoleAppender.Target.SYSTEM_OUT)
                .setLayout(PatternLayout.newBuilder().withPattern(CONVERSION_PATTERN).build())
                .setName(CONSOLE_APPENDER_NAME))
                .build();
        consoleAppender.start();

        loggerConfig.addAppender(consoleAppender, null, null);
        ctx.updateLoggers();
    }

    private void setLoggingToStdOut() {
        String logFileName = NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_NAME, LogFileHelper.DEFAULT_LOG_FILE_NAME);
        isLoggingToStdOut = StringUtils.equals(LogFileHelper.STDOUT, logFileName);
    }
}
