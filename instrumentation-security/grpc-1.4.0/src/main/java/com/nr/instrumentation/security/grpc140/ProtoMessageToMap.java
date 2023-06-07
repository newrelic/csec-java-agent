package com.nr.instrumentation.security.grpc140;

import com.google.protobuf.Descriptors;
import com.google.protobuf.MapEntry;
import com.google.protobuf.MessageOrBuilder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ProtoMessageToMap {
    static Map<String, Object> convertibleMessageFormat(MessageOrBuilder message) {
        Map<String, Object> messageMap = new HashMap<>();
        for (Map.Entry<Descriptors.FieldDescriptor, Object> entry : message.getAllFields().entrySet()) {
            String key = entry.getKey().getName();
            Object value = entry.getValue();

            if (value instanceof MessageOrBuilder) {
                messageMap.put(key, convertibleMessageFormat((MessageOrBuilder)value));
            } else if (value instanceof Collection) {
                boolean isMap = !((Collection<?>)value).isEmpty() && ((Collection<?>)value).iterator().next() instanceof MapEntry;
                if (isMap){
                    messageMap.put(key, convertListToMap((Collection)value));
                } else {
                    messageMap.put(key, convertibleMessageFormat((Collection<Object>)value));
                }
            } else {
                messageMap.put(key, value);
            }
        }
        return messageMap;
    }

    private static Collection<Object> convertibleMessageFormat(Collection<Object> received) {
        Collection<Object> list = new ArrayList<>();
        for (Object value : received) {
            if (value instanceof MessageOrBuilder) {
                list.add(convertibleMessageFormat((MessageOrBuilder) value));
            } else if (value instanceof Collection) {
                list.add(convertibleMessageFormat((Collection<Object>) value));
            } else {
                list.add(value);
            }
        }
        return list;
    }

    public static Map<Object, Object> convertListToMap(Collection<MapEntry<Object, Object>> entryList) {
        Map<Object, Object> messageMap = new HashMap<>();
        for (MapEntry<Object, Object> entry : entryList) {
            Object key = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof MessageOrBuilder) {
                messageMap.put(key, convertibleMessageFormat((MessageOrBuilder)value));
            } else if (value instanceof Collection) {
                boolean isMap = !((Collection<?>)value).isEmpty() && ((Collection<?>)value).iterator().next() instanceof MapEntry;
                if (isMap){
                    messageMap.put(key, convertListToMap((Collection)value));
                } else {
                    messageMap.put(key, convertibleMessageFormat((Collection<Object>)value));
                }
            } else {
                messageMap.put(key, value);
            }
        }
        return messageMap;
    }
}
