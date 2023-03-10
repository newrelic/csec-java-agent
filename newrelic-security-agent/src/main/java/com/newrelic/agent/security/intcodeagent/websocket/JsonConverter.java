package com.newrelic.agent.security.intcodeagent.websocket;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.serializers.K2StackTraceSerializer;
import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.Map.Entry;

public class JsonConverter {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static final String JSON_SEPRATER = "\":";
    private static final String STR_FORWARD_SLASH = "\"";
    private static final String STR_COMMA = ",";
    private static final String STR_END_CUELY_BRACKET = "}";
    private static final String STR_START_CUELY_BRACKET = "{";

    private static ObjectMapper mapper;

    private static String serializerSelection = System.getenv().getOrDefault("K2_JSON_SERIALIZER", "Jackson");

    static {
        ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        SimpleModule module = new SimpleModule();
        module.addSerializer(StackTraceElement.class, new K2StackTraceSerializer());
        objectMapper = objectMapper.registerModule(module);

        objectMapper = objectMapper.setAnnotationIntrospector(new JacksonAnnotationIntrospector() {

            @Override
            public boolean hasIgnoreMarker(AnnotatedMember m) {
                return _findAnnotation(m, JsonIgnore.class) != null;
            }
        });
        mapper = objectMapper;
    }

    public static String toJSON(Object obj) {

        switch (serializerSelection) {
            case "K2":
                return toJSONK2Impl(obj);
            default:
            case "Jackson":
                return toJSONObjectMapper(obj);
        }
    }

    public static String toJSONObjectMapper(Object obj) {
        try {
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            return StringUtils.EMPTY;
        }
    }

    public static String toJSONK2Impl(Object obj) {
        StringBuilder jsonString = new StringBuilder(STR_START_CUELY_BRACKET);

        Class<?> objClass = obj.getClass();
        Class<?> superClass = obj.getClass().getSuperclass();

        List<Field> fields = new ArrayList<>();

        Field[] superFields = superClass.getDeclaredFields();
        fields.addAll(Arrays.asList(superFields));
        Field[] objFields = objClass.getDeclaredFields();
        fields.addAll(Arrays.asList(objFields));
        jsonString.append(getFieldsAsJsonString(fields, obj));
        jsonString.append(STR_END_CUELY_BRACKET);
        return jsonString.toString();
    }

    public static String toJSONMap(Map obj) {
        StringBuilder jsonString = new StringBuilder();
        JSONObject mapObject = new JSONObject();
        mapObject.putAll(processMap(obj));
        jsonString.append(mapObject.toJSONString());
        return jsonString.toString();
    }

    private static String getFieldsAsJsonString(List<Field> fields, Object obj) {
        StringBuilder jsonString = new StringBuilder();
        for (int i = 0; i < fields.size(); i++) {
            Object value = null;
            try {
                if (!Modifier.isStatic(fields.get(i).getModifiers()) || fields.get(i).getAnnotation(JsonInclude.class) != null) {
                    Field field = fields.get(i);
                    field.setAccessible(true);
                    if (field.getAnnotation(JsonIgnore.class) != null) {
                        continue;
                    }
                    value = field.get(obj);
                    if (value != null) {
                        jsonString.append(STR_FORWARD_SLASH);
                        jsonString.append(field.getName());
                        jsonString.append(JSON_SEPRATER);
                        if (field.getType().equals(String.class) || field.getType().isEnum()) {
                            jsonString.append(STR_FORWARD_SLASH);
                            jsonString.append(StringEscapeUtils.escapeJava(value.toString()));
                            jsonString.append(STR_FORWARD_SLASH);
                        } else if (field.getType().isPrimitive()) {
                            jsonString.append(value);
                        } else if (field.getType().isAssignableFrom(Set.class)) {
                            JSONArray setField = new JSONArray();
                            setField.addAll(processCollection((Collection) value));
                            jsonString.append(setField);
                        } else if (field.getType().isArray()) {
                            JSONArray setField = new JSONArray();
                            setField.addAll(processCollection(Arrays.asList((Object[]) value)));
                            jsonString.append(setField);
                        } else if (field.getType().isAssignableFrom(List.class)) {
                            JSONArray setField = new JSONArray();
                            setField.addAll(processCollection((Collection) value));
                            jsonString.append(setField);
                        } else if (field.getType().isAssignableFrom(Map.class)) {
                            JSONObject mapField = new JSONObject();
                            mapField.putAll(processMap((Map) value));
                            jsonString.append(mapField);
                        } else {
                            jsonString.append(value.toString());
                        }
                        jsonString.append(STR_COMMA);
                    }
                }
            } catch (IllegalArgumentException | IllegalAccessException e) {
            } catch (Exception e) {
                try {
                    logger.log(LogLevel.SEVERE, "Can't cast value : " + new ObjectMapper().writeValueAsString(value), e, JsonConverter.class.getName());
                } catch (JsonProcessingException ex) {
                }
            }
        }
        return StringUtils.removeEnd(jsonString.toString(), STR_COMMA);
    }

    private static Map processMap(Map<String, Object> value) {
        Map<String, Object> mapObject = new HashMap<>();
        for (Entry<String, Object> entry : value.entrySet()) {
            mapObject.put(entry.getKey(), processValue(entry.getValue()));
        }

        return mapObject;
    }

    private static Object processValue(Object value) {
        if (value instanceof Collection) {
            return processCollection((Collection<Object>) value);
        } else if (value instanceof Object[]) {
            return processCollection(Arrays.asList((Object[]) value));
        } else if (value instanceof Map) {
            return processMap((Map) value);
        } else if (value instanceof StackTraceElement) {
            return AgentUtils.stackTraceElementToString((StackTraceElement) value);
        } else {
            return value;
        }
    }

    private static Collection processCollection(Collection<Object> values) {
        List<Object> list = new ArrayList<>();
        for (Object value : values) {
            if (value instanceof Collection || value instanceof Object[]) {
                list.addAll((Collection<? extends Object>) processValue(value));
            } else {
                list.add(processValue(value));
            }
        }
        return list;
    }

    public static ObjectMapper getObjectMapper() {
        return mapper;
    }

    //	public static void main(String[] args) {
//
//		String[] arr = new String[] {"as", "vd"};
//
//
//		JavaAgentEventBean javaAgentEventBean = new JavaAgentEventBean(System.currentTimeMillis(), 15L, "source", 12121,
//				"asdasd-1212-sdf", "12-12", VulnerabilityCaseType.SQL_DB_COMMAND);
//		JSONArray jsonArray = new JSONArray();
//		jsonArray.add("sadasda");
//		jsonArray.add("sadasdaasdfasd");
//		jsonArray.addAll(Arrays.asList(arr));
//		javaAgentEventBean.setParameters(jsonArray);
//
//		javaAgentEventBean.setStacktrace(Arrays.asList(Thread.currentThread().getStackTrace()));
//
//		System.out.println(javaAgentEventBean.toString());
//	}
}
