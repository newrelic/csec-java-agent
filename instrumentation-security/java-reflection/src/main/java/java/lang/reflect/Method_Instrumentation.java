package java.lang.reflect;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.JavaReflectionOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Weave(type = MatchType.ExactClass, originalName = "java.lang.reflect.Method")
public abstract class Method_Instrumentation {

    public abstract String getName();

    public abstract Class<?> getDeclaringClass();

    public abstract Class<?>[] getParameterTypes();

    public Object invoke(Object obj, Object... args) {
        AbstractOperation operation = null;
        if(NewRelicSecurity.isHookProcessingActive()) {
            operation = preprocessSecurityHook(obj, getDeclaringClass(), getParameterTypes(), getName(), args);
        }
        Object returnValue = Weaver.callOriginal();
        registerExitOperation(operation);
        return returnValue;
    }

    private void registerExitOperation(AbstractOperation operation) {
        NewRelicSecurity.getAgent().registerExitEvent(operation);
    }

    private AbstractOperation preprocessSecurityHook(Object obj, Class<?> declaringClass, Class<?>[] parameterTypes, String name, Object[] args) {
        try {
            if (NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation() != null && NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation().getActive()) {
                if(StringUtils.isNotBlank(NewRelicSecurity.getAgent().getSecurityMetaData().getDeserializationInvocation().peekReadObjectInAction())
                    && !StringUtils.equals(name, "readObject")) {
                    JavaReflectionOperation operation = new JavaReflectionOperation(this.getClass().getName(), "invoke", declaringClass.getName(), name, args, obj);
                    List<String> methodNames = new ArrayList<>();
                    for (Method method : declaringClass.getDeclaredMethods()) {
                        if(Arrays.equals(method.getParameterTypes(), parameterTypes)) {
                            methodNames.add(method.getName());
                        }
                    }
                    operation.setDeclaredMethods(methodNames);
                    NewRelicSecurity.getAgent().registerOperation(operation);
                    return operation;
                }
            }
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, "JAVA-REFLECTION", e.getMessage()), e, Method_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JAVA-REFLECTION", e.getMessage()), e, Method_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JAVA-REFLECTION", e.getMessage()), e, Method_Instrumentation.class.getName());
        }
        return null;
    }
}
