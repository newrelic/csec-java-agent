package com.newrelic.api.agent.security.instrumentation.helpers.serializer;

import java.io.ObjectStreamClass;
import java.lang.reflect.Constructor;

public class ObjectInstanceFactory {

    public static Object createInstance(Class<?> clazz) throws Exception {
        ObjectStreamClass osc = ObjectStreamClass.lookup(clazz);
        if (osc == null) {
            throw new IllegalArgumentException("Class not serializable: " + clazz.getName());
        }

        Constructor<?> constructor = clazz.getDeclaredConstructor();
        return constructor.newInstance();
    }

    public static Class<?> getClassByName(String className) throws ClassNotFoundException {
        return Class.forName(className);
    }

    

}
