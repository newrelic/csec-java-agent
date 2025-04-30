package com.newrelic.agent.security.intcodeagent.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.*;

/**
 * Utility class for serializing and deserializing objects.
 */
public class SerializerUtil {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static final Map<Class<?>, Object> dummyValues = new HashMap<>();

    static {
        dummyValues.put(int.class, 0);
        dummyValues.put(Integer.class, 0);
        dummyValues.put(long.class, 0L);
        dummyValues.put(Long.class, 0L);
        dummyValues.put(double.class, 0.0);
        dummyValues.put(Double.class, 0.0);
        dummyValues.put(float.class, 0.0f);
        dummyValues.put(Float.class, 0.0f);
        dummyValues.put(boolean.class, false);
        dummyValues.put(Boolean.class, false);
        dummyValues.put(String.class, "dummy");
    }

    /**
     * Serializes an object to a byte array.
     *
     * @param obj the object to serialize
     * @return the byte array representation of the object, or null if serialization fails
     */
    public static byte[] serialize(Object obj) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(obj);
            oos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.log(LogLevel.WARNING, String.format("Unable to serialize object : %s: %s", obj, e.getMessage()), CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format("Unable to serialize object : %s", obj), e, CommonUtils.class.getName());
        }
        return null;
    }

    /**
     * Instantiates an object from its JSON string representation.
     *
     * @param data  the JSON string representation of the object
     * @param klass the class of the object to instantiate
     * @return the instantiated object, or null if instantiation fails
     */
    public static Object instantiate(String data, Class<?> klass) {
        try {
            return JsonConverter.getObjectMapper().readValue(data, klass);
        } catch (JsonProcessingException e) {
            logger.log(LogLevel.WARNING, String.format("Unable to instantiate object : %s: %s", klass, e.getMessage()), CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format("Unable to instantiate object : %s", klass), e, CommonUtils.class.getName());
        }
        return null;
    }

    /**
     * Encodes a byte array to a base64 string.
     *
     * @param data the byte array to encode
     * @return the base64 string representation of the byte array
     */
    public static String base64Encode(byte[] data) {
        return java.util.Base64.getEncoder().encodeToString(data);
    }


    /**
     * Retrieves the Class object associated with the class or interface with the given string name.
     *
     * @param className the fully qualified name of the desired class
     * @return the Class object for the class with the specified name
     * @throws ClassNotFoundException if the class cannot be located
     */
    public static Class<?> getClassByName(String className) throws ClassNotFoundException {
        return Class.forName(className);
    }

    /**
     * Serializes an object to a byte array, then encodes the byte array to a base64 string.
     *
     * @param className the fully qualified name of the class of the object to serialize
     * @param jsonData  the JSON string representation of the object
     * @return the base64 string representation of the serialized object, or null if serialization fails
     */
    public static String base64SerializedPayload(String className, String jsonData) {
        try {
            Class<?> clazz = getClassByName(className);
            Object obj = instantiate(jsonData, clazz);
            byte[] serialized = serialize(obj);
            return base64Encode(serialized);
        } catch (ClassNotFoundException e) {
            logger.log(LogLevel.WARNING, String.format("Unable to base64 serialize object : %s: %s", className, e.getMessage()), CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format("Unable to base64 serialize object : %s", className), e, CommonUtils.class.getName());
        }
        return null;
    }

    public static <T> T createDummyObject(Class<T> clazz, List<String> fields) throws IllegalAccessException, InstantiationException {
        T instance = clazz.newInstance();
        for (Field field : clazz.getDeclaredFields()) {
            if(fields.contains(field.getName())) {
                field.setAccessible(true);
                setDummyValue(instance, field);
            }
        }
        return instance;
    }

    public static <T> T createDummyObject(Class<T> clazz) throws IllegalAccessException, InstantiationException {
        T instance = clazz.newInstance();
        for (Field field : clazz.getDeclaredFields()) {
            field.setAccessible(true);
            setDummyValue(instance, field);
        }
        return instance;
    }

    private static void setDummyValue(Object instance, Field field) throws IllegalAccessException, InstantiationException {
        Class<?> fieldType = field.getType();
        if (dummyValues.containsKey(fieldType)) {
            field.set(instance, dummyValues.get(fieldType));
        } else if (List.class.isAssignableFrom(fieldType)) {
            List<Object> dummyList = new ArrayList<>();
            dummyList.add(Runtime.class);
            field.set(instance, dummyList);
        } else if (Map.class.isAssignableFrom(fieldType)) {
            Map<Object, Object> dummyMap = new HashMap<>();
            dummyMap.put("dummyKey", Runtime.class);
            field.set(instance, dummyMap);
        } else if (Set.class.isAssignableFrom(fieldType)) {
            Set<Object> dummySet = new HashSet<>();
            dummySet.add(Runtime.class);
            field.set(instance, dummySet);
        } else if (fieldType.isArray()) {
            int dimensions = getArrayDimensions(fieldType);
            Object arrayInstance = createArrayInstance(fieldType.getComponentType(), dimensions);
            if (dimensions == 1) {
                Array.set(arrayInstance, 0, dummyValues.getOrDefault(fieldType.getComponentType(), Runtime.class));
            }
            field.set(instance, arrayInstance);
        } else if (!fieldType.isPrimitive()) {
            field.set(instance, createDummyObject(fieldType));
        }
    }

    private static int getArrayDimensions(Class<?> arrayClass) {
        int dimensions = 0;
        Class<?> currentClass = arrayClass;
        while (currentClass.isArray()) {
            dimensions++;
            currentClass = currentClass.getComponentType();
        }
        return dimensions;
    }

    private static Object createArrayInstance(Class<?> componentType, int dimensions) {
        int[] dimensionSizes = new int[dimensions];
        Arrays.fill(dimensionSizes, 1); // Initialize each dimension with size 1
        return Array.newInstance(componentType, dimensionSizes);
    }



}
