package com.newrelic.api.agent.security.schema;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;

public class DeserializationInfo implements Serializable {
    final static int MAX_DEPTH_POPULATION = 10;
    final static Set<Class> PRIMITIVE_WRAPPERS = new HashSet<Class>() {{
        add(Boolean.class);
        add(Character.class);
        add(Byte.class);
        add(Short.class);
        add(Integer.class);
        add(Long.class);
        add(Float.class);
        add(Double.class);
        add(Void.class);
        add(boolean.class);
        add(char.class);
        add(byte.class);
        add(short.class);
        add(int.class);
        add(long.class);
        add(float.class);
        add(double.class);
        add(void.class);
    }};

    private String type;
    private boolean leaf;
    private Map<String, DeserializationInfo> value;
    private String leafValue;
    private Object instance;

    public DeserializationInfo(String type, Object instance) {
        this.type = type;
        this.instance = instance;
        this.leaf = false;
    }

    public DeserializationInfo(String type, Object instance, Map<String, DeserializationInfo> value) {
        this.type = type;
        this.instance = instance;
        this.leaf = false;
        this.value = value;
    }

    public DeserializationInfo(String type, Object instance, String value) {
        this.type = type;
        this.instance = instance;
        this.leaf = true;
        this.leafValue = value;
    }

    public DeserializationInfo(DeserializationInfo instance) {
        this.type = instance.type;
        this.leaf = instance.leaf;
        if (instance.leaf){
            this.leafValue = instance.leafValue;
        } else {
            this.value = new HashMap<>();
            this.value.putAll(instance.value);
        }
    }
    public DeserializationInfo() {
        this.type = "";
        this.leaf = false;
        this.value = new HashMap<>();
        this.leafValue = "";
    }


    public Map<String, DeserializationInfo> computeAttributeFlatMap() {
        if (this.value == null || this.leafValue == null || this.leafValue.isEmpty()) {
            try {
                this.value = computeKeyValueMappingOnObject(this.instance, 0);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        return this.value;
    }

    private Map<String, DeserializationInfo> computeKeyValueMappingOnObject(Object obj, int depth) throws IllegalAccessException {
        Map<String, DeserializationInfo> valueMap = new HashMap<>();
        if (depth > MAX_DEPTH_POPULATION){
            return new HashMap<>();
        }
        try {
            Field[] fields = obj.getClass().getFields();
            for (Field field : fields) {
                boolean accessibility = field.isAccessible();
                field.setAccessible(true);
                Object val = field.get(obj);
                populateForField(val, field.getName(), valueMap, depth++);
                field.setAccessible(accessibility);
            }
            List<Field> fieldList = getAllPrivateFields(obj.getClass());
            for (Field field : fieldList) {
                boolean accessibility = field.isAccessible();
                field.setAccessible(true);
                Object val = field.get(obj);
                populateForField(val, field.getName(), valueMap, depth++);
                field.setAccessible(accessibility);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return valueMap;
    }

    private void populateForField(Object obj, String name, Map<String, DeserializationInfo> valueMap, int depth) throws IllegalAccessException {
        if (depth > MAX_DEPTH_POPULATION || obj == null || name == null || valueMap == null){
            return;
        }
        boolean primitiveObj = obj.getClass().isPrimitive() || PRIMITIVE_WRAPPERS.contains(obj.getClass());
        if (primitiveObj) {
            return;
        }

        if (obj.getClass() == String.class) {
            DeserializationInfo entry = new DeserializationInfo(obj.getClass().getName(), obj, (String) obj);
            valueMap.put(name, entry);
        } else if (Collection.class.isAssignableFrom(obj.getClass())) {
            Object col[] = ((Collection) obj).toArray();
            Map<String, DeserializationInfo> collectionMap = new HashMap<>();
            for (int elementIndex=0; elementIndex<col.length; elementIndex++) {
                populateForField(col[elementIndex], String.valueOf(elementIndex), collectionMap, depth + 1);
            }
            DeserializationInfo entry = new DeserializationInfo(obj.getClass().getName(), obj, collectionMap);
            valueMap.put(name, entry);
        } else {
            DeserializationInfo entry = new DeserializationInfo(
                    obj.getClass().getName(), obj, computeKeyValueMappingOnObject(obj, depth + 1)
            );
            valueMap.put(name, entry);
        }
    }

    private List<Field> getAllPrivateFields(Class<?> clz){
        List<Field> fields = new ArrayList<>();
        fields.addAll(Arrays.asList(clz.getDeclaredFields()));
        Class<?> superClass = clz.getSuperclass();
        if (superClass != null && (PRIMITIVE_WRAPPERS.contains(superClass) || superClass == Object.class)){
            fields.addAll(getAllPrivateFields(superClass));
        }
        return  fields;
    }

    private Map<String, String> getFlatMap(Map<String, Map.Entry> identifierMap){
        Map<String, String> flatMap = new HashMap<>();
        for (Map.Entry<String, Map.Entry> entry : identifierMap.entrySet()) {
            if (entry.getValue().getKey() == String.class.getName()) {
                flatMap.put(entry.getKey(), (String) entry.getValue().getValue());
            } else if (Map.class.isAssignableFrom(entry.getValue().getValue().getClass())){
                Map<String, Map.Entry> valMap = (Map<String, Map.Entry>) entry.getValue().getValue();
                Map<String, String> childFlatMap = getFlatMap(valMap);
                for (Map.Entry<String, String> childEntry : childFlatMap.entrySet()){
                    String key = String.format("%s.%s", entry.getKey(), childEntry.getKey());
                    flatMap.put(key, childEntry.getValue());
                }
            }
        }
        return flatMap;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isLeaf() {
        return leaf;
    }

    public void setLeaf(boolean leaf) {
        this.leaf = leaf;
    }

    public Map<String, DeserializationInfo> getValue() {
        return value;
    }

    public void setValue(Map<String, DeserializationInfo> value) {
        this.value = value;
    }

    public String getLeafValue() {
        return leafValue;
    }

    public void setLeafValue(String leafValue) {
        this.leafValue = leafValue;
    }

    public Object getInstance() {
        return instance;
    }

    public void setInstance(Object instance) {
        this.instance = instance;
    }
}