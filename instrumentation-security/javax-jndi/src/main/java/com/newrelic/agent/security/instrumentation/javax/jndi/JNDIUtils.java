package com.newrelic.agent.security.instrumentation.javax.jndi;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;

import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class JNDIUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "JNDI_OPERATION_LOCK-";
    public static final String METHOD_LOOKUP = "lookup";

    public static List<AbstractOperation> handleJNDIHook(Enumeration<String> names, String methodName, String className) {
        List<AbstractOperation> abstractOperations = new ArrayList<>();
        while (names.hasMoreElements()) {
            abstractOperations.add(handleJNDIHook(names.nextElement(), methodName, className));
        }
        return abstractOperations;
    }

    public static AbstractOperation handleJNDIHook(String name, String methodName, String className) {
        try {
            URI url = new URI(name);
            if (StringUtils.isNotBlank(url.getScheme()) &&
                    StringUtils.equalsAny(url.getScheme().toLowerCase(), "ldap", "rmi", "dns", "iiop")) {
                SSRFOperation operation = new SSRFOperation(name, className, methodName, true);
                NewRelicSecurity.getAgent().registerOperation(operation);
                return operation;
            }
        } catch (Exception ignored) {}
        return null;
    }

}
