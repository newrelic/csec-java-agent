package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.util.List;

public class JavaReflectionOperation extends AbstractOperation {

    private String declaringClass;

    private String nameOfMethod;

    private Object[] args;

    private Object obj;

    private List<String> declaredMethods;

    public JavaReflectionOperation(String className, String methodName, String declaringClass, String nameOfMethod,Object[] args, Object obj) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.REFLECTION);
        this.declaringClass = declaringClass;
        this.nameOfMethod = nameOfMethod;
        this.args = args;
        this.obj = obj;
    }

    public String getDeclaringClass() {
        return declaringClass;
    }

    public void setDeclaringClass(String declaringClass) {
        this.declaringClass = declaringClass;
    }

    public Object getObj() {
        return obj;
    }

    public void setObj(Object obj) {
        this.obj = obj;
    }

    public Object[] getArgs() {
        return args;
    }

    public void setArgs(Object[] args) {
        this.args = args;
    }

    public String getNameOfMethod() {
        return nameOfMethod;
    }

    public void setNameOfMethod(String nameOfMethod) {
        this.nameOfMethod = nameOfMethod;
    }

    public List<String> getDeclaredMethods() {
        return declaredMethods;
    }

    public void setDeclaredMethods(List<String> declaredMethods) {
        this.declaredMethods = declaredMethods;
    }

    @Override
    public boolean isEmpty() {
        return (declaringClass == null || declaringClass.trim().isEmpty());
    }
}
