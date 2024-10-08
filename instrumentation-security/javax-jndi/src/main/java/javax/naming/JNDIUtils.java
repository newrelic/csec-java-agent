package javax.naming;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class JNDIUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "JNDI_OPERATION_LOCK-";
    public static final String METHOD_LOOKUP = "lookup";
    public static final String JAVAX_JNDI = "JAVAX-JNDI";

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
        } catch (URISyntaxException ignored) {
            // Ignoring URISyntaxException
        }
        catch (Exception ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JAVAX_JNDI, ignored.getMessage()), ignored, JNDIUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JAVAX_JNDI, ignored.getMessage()), ignored, JNDIUtils.class.getName());
        }
        return null;
    }

}
