package com.newrelic.api.agent.security.instrumentation.helpers;

//import com.google.protobuf.InvalidProtocolBufferException;
//import com.google.protobuf.MessageOrBuilder;
//import com.google.protobuf.util.JsonFormat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GrpcHelper {
    public static <M> StringBuilder convertToJsonString(M message, StringBuilder original) {
        String decodedString = "";
        try {
            ObjectMapper objectMapper = new ObjectMapper().configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            decodedString = objectMapper.writeValueAsString(message);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        if (StringUtils.isBlank(original)) {
            return new StringBuilder("[" + decodedString + "]");
        }
        else {
            return convertToJsonArray(String.valueOf(original), decodedString);
        }
    }

    private static StringBuilder convertToJsonArray(String original, String current) {
        StringBuilder jsonBuilder = new StringBuilder(original);
        if (jsonBuilder.length() > 0 && jsonBuilder.charAt(jsonBuilder.length() - 1) == ']') {
            jsonBuilder.deleteCharAt(jsonBuilder.length() - 1);
        }
        jsonBuilder.append(",");
        jsonBuilder.append(current);
        jsonBuilder.append("]");
        return jsonBuilder;
    }

    public static String getFormattedIp(String input) {
        Pattern ipv4Regex = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");
        Pattern ipv6Regex = Pattern.compile("([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}");

        Matcher ipv4 = ipv4Regex.matcher(input);
        if (ipv4.find()) {
            return ipv4.group();
        }

        Matcher ipv6 = ipv6Regex.matcher(input);
        if (ipv6.find()) {
            return ipv6.group();
        }

        return "";
    }

    public static String getPort(String input) {
        String[] strings = input.split(":");
        return strings[strings.length-1];
    }
}
