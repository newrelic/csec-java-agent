package com.k2cybersecurity.instrumentator.decorators.httpservice;

import com.k2cybersecurity.instrumentator.decorators.httpservice.utils.CacheInputStream;
import com.k2cybersecurity.instrumentator.decorators.httpservice.utils.Utils;
import com.k2cybersecurity.intcodeagent.logging.ExecutionMap;
import com.k2cybersecurity.intcodeagent.logging.ServletEventPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.COLON_SEPERATOR;

public class Callbacks {

    public static void doOnEnter(String sourceString, Object obj, Object[] args, String exectionId) {
        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
        HttpRequestBean httpRequestBean = new HttpRequestBean();
        long threadId = Thread.currentThread().getId();
        Long executionId = Long.parseLong(exectionId.split(COLON_SEPERATOR)[1]);

        ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
        executionMaps.add(new ExecutionMap(executionId, httpRequestBean));
        ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);


        try {
            Object httpRequest = args[0];
            Object httpResponse = args[0];
            Class requestClass = httpRequest.getClass();
            Class responsetClass = httpResponse.getClass();

            Method getMethod = requestClass.getMethod("getMethod");
            httpRequestBean.setMethod((String)getMethod.invoke(httpRequest, null));

            Method getRemoteAddr = requestClass.getMethod("getRemoteAddr");
            httpRequestBean.setClientIP((String)getRemoteAddr.invoke(httpRequest, null));

            Map<String, String> headers = new HashMap<>();
            Utils.processHeaders(headers, httpRequest);
            httpRequestBean.setHeaders(new JSONObject(headers));

            Method getRequestURI = requestClass.getMethod("getRequestURI");
            httpRequestBean.setUrl((String)getRequestURI.invoke(httpRequest, null));

            Method getInputStream = requestClass.getMethod("getInputStream");
            InputStream inputStream = (InputStream)getInputStream.invoke(httpRequest, null);

//            CacheInputStream cacheInputStream = new CacheInputStream(inputStream);
//
//            Field inputStreamField = requestClass.getField("inputStream");
//            inputStreamField.setAccessible(true);
//            inputStreamField.set(inputStream, (InputStream)cacheInputStream);
//            httpRequestBean.setCacheInputStream(cacheInputStream);

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Source : " + sourceString + " :::: "+httpRequestBean);
    }

    public static void doOnExit(String sourceString, Object obj, Object[] args, Object returnVal, String exectionId) {
        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
        long threadId = Thread.currentThread().getId();
        Long executionId = Long.parseLong(exectionId.split(COLON_SEPERATOR)[1]);
        Pair<HttpRequestBean, AgentMetaData> data = ExecutionMap.find(executionId, ServletEventPool.getInstance().getRequestMap().get(threadId));
        HttpRequestBean servletInfo = data.getLeft();
        try {
            System.out.println("Data on exit : " + IOUtils.toString(servletInfo.getCacheInputStream().readCurrentCache()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void doOnError(String sourceString, Object obj, Object[] args, Throwable error, String exectionId) throws Throwable {
        System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
        throw error;
    }
}
