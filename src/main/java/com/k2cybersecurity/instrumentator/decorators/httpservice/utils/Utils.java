package com.k2cybersecurity.instrumentator.decorators.httpservice.utils;

import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class Utils {

    public static void processHeaders(Map<String, String> headers, Object httpRequest){
        try {
            Class requestClass = httpRequest.getClass();

            Method getHeaderNames = requestClass.getMethod("getHeaderNames", null);
            Method getHeaders = requestClass.getMethod("getHeaders", String.class);

            Enumeration<String> attribs = ((Enumeration<String>) getHeaderNames.invoke(httpRequest, null));
            while(attribs.hasMoreElements()){
                String headerKey = attribs.nextElement();
                String headerFullValue = StringUtils.EMPTY;
                Enumeration<String> headerElements = (Enumeration<String>) getHeaders.invoke(httpRequest, headerKey);
                while (headerElements.hasMoreElements()) {
                    String headerValue = headerElements.nextElement();
                    if(headerFullValue.isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue += "; "+headerValue;
                    }
                }
                headers.put(headerKey, headerFullValue);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
