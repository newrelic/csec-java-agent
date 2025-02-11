package com.newrelic.agent.security.intcodeagent.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.newrelic.agent.security.intcodeagent.exceptions.RestrictionModeException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.StringBuilderLimit;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.policy.RestrictionCriteria;
import com.newrelic.api.agent.security.schema.policy.SkipScan;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.*;
import java.util.regex.Pattern;

public class RestrictionUtility {

    public static final String SEPARATOR_CHARS_QUESTION_MARK = "?";
    public static final String SEPARATOR_CHARS_SEMICOLON = ";";
    public static final String FORWARD_SLASH = "/";
    public static final String AND = "&";
    public static final String SEPARATOR_EQUALS = "=";
    public static final String EQUAL = "=";
    public static final String CONTENT_TYPE_TEXT_JSON = "text/json";
    public static final String CONTENT_TYPE_TEXT_XML = "text/xml";
    public static final String CONTENT_TYPE_APPLICATION_JSON = "application/json";
    public static final String CONTENT_TYPE_APPLICATION_XML = "application/xml";
    public static final String CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static boolean skippedApiDetected(SkipScan skipScan, HttpRequest httpRequest) {
        if (skipScan == null) {
            return false;
        }
        if (httpRequest == null) {
            return false;
        }

        if(skipScan.getApiRoutes().isEmpty()) {
            return false;
        }

        for (Pattern pattern : skipScan.getApiRoutes()) {
            if (pattern.matcher(httpRequest.getUrl()).matches()) {
                return true;
            }
        }

        return false;
    }

    public static boolean hasValidAccountId(RestrictionCriteria restrictionCriteria, HttpRequest request) {
        List<String> accountIds = restrictionCriteria.getAccountInfo().getAccountIds();
        if (request == null) {
            return false;
        }
        if(!request.isRequestParametersParsed()){
            parseHttpRequestParameters(request);
        }

        if(restrictionCriteria.getMappingParameters().getHeader().isEnabled()) {
            Set<String> headerValues = getHeaderParameters(restrictionCriteria.getMappingParameters().getHeader().getLocations(), request.getRequestHeaderParameters());
            if(matcher(accountIds, headerValues)){
                return true;
            }
        }
        if(restrictionCriteria.getMappingParameters().getQuery().isEnabled()) {
            Set<String> queryValues = getQueryString(restrictionCriteria.getMappingParameters().getHeader().getLocations(), request.getQueryParameters());
            if(matcher(accountIds, queryValues)){
                return true;
            }
        }
        if(restrictionCriteria.getMappingParameters().getPath().isEnabled()) {
            if(matcher(accountIds, request.getPathParameters())){
                return true;
            }
        }
        if(restrictionCriteria.getMappingParameters().getBody().isEnabled()) {
            Set<String> bodyValues = getBodyParameters(restrictionCriteria.getMappingParameters().getBody().getLocations(), request.getRequestBodyParameters());
            return matcher(accountIds, bodyValues);
        }

        return false;
    }

    private static Set<String> getBodyParameters(List<String> accountIds, Map<String, Set<String>> requestBodyParameters) {
        if (requestBodyParameters == null || requestBodyParameters.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> values = new HashSet<>();
        for (String accountId : accountIds) {
            String lowerCaseAccountId = accountId.toLowerCase();
            if(requestBodyParameters.containsKey(lowerCaseAccountId)) {
                values.addAll(requestBodyParameters.get(lowerCaseAccountId));
            }
        }

        return values;
    }

    private static Set<String> getHeaderParameters(List<String> accountIds, Map<String, Set<String>> requestHeaderParameters) {
        if (requestHeaderParameters == null || requestHeaderParameters.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> values = new HashSet<>();
        for (String accountId : accountIds) {
            String lowerCaseAccountId = accountId.toLowerCase();
            if(requestHeaderParameters.containsKey(lowerCaseAccountId)) {
                values.addAll(requestHeaderParameters.get(lowerCaseAccountId));
            }
        }
        return values;
    }

    private static Set<String> getQueryString(List<String> accountIds, Map<String, Set<String>> queryParameters) {
        if(queryParameters == null || queryParameters.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> values = new HashSet<>();
        for (String accountId : accountIds) {
            String lowerCaseAccountId = accountId.toLowerCase();
            if(queryParameters.containsKey(lowerCaseAccountId)) {
                values.addAll(queryParameters.get(lowerCaseAccountId));
            }
        }
        return values;
    }

    private static boolean matcher(List<String> accountIds, Set<String> values) {
        for (String accountId : accountIds) {
            if(values == null || values.isEmpty() || StringUtils.isBlank(accountId)) {
                continue;
            }
            String lowerCaseAccountId = accountId.toLowerCase();
            boolean contains = values.contains(lowerCaseAccountId);
            if(contains){
                return true;
            }
        }
        return false;
    }

    private static void parseHttpRequestParameters(HttpRequest request) {
        request.setPathParameters(parsePathParameters(StringUtils.substringBefore(request.getUrl(),
                SEPARATOR_CHARS_QUESTION_MARK)));
        request.setQueryParameters(parseQueryParameters(request.getUrl()));
        request.setRequestHeaderParameters(parseRequestHeaders(request.getHeaders()));
        try {
            request.setRequestBodyParameters(parseRequestBody(request.getBody().getSb(), request.getContentType(), request.getRequestBodyParameters()));
        } catch (RestrictionModeException e) {
            logger.log(LogLevel.WARNING, String.format("Request Body parsing failed reason %s", e.getMessage()), RestrictionUtility.class.getName());
        }
        request.setRequestBodyParameters(parseRequestParameterMap(request.getParameterMap(), request.getRequestBodyParameters()));
        request.setRequestParametersParsed(true);
    }

    private static Map<String, Set<String>> parseRequestParameterMap(Map<String, String[]> parameterMap, Map<String, Set<String>> requestBodyParameters) {
        if(parameterMap == null) {
            return requestBodyParameters;
        }
        if(requestBodyParameters == null) {
            requestBodyParameters = new HashMap<>();
        }

        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            String key = entry.getKey();
            String[] values = entry.getValue();
            Set<String> valuesList = new HashSet<>();
            for (String value : values) {
                valuesList.add(StringUtils.lowerCase(value));
            }
            if(requestBodyParameters.containsKey(key)){
                requestBodyParameters.get(key).addAll(valuesList);
            } else {
                requestBodyParameters.put(key, valuesList);
            }
        }
        return requestBodyParameters;
    }

    private static Map<String, Set<String>> parseRequestBody(StringBuilder body, String contentType, Map<String, Set<String>> requestBodyParameters) throws RestrictionModeException {
        if(StringUtils.isBlank(body.toString())) {
            return requestBodyParameters;
        }

        if(requestBodyParameters == null) {
            requestBodyParameters = new HashMap<>();
        }

        switch (contentType) {
            case CONTENT_TYPE_APPLICATION_JSON:
            case CONTENT_TYPE_TEXT_JSON:
                requestBodyParameters.putAll(parseJsonRequestBody(body.toString()));
                break;
            case CONTENT_TYPE_APPLICATION_XML:
            case CONTENT_TYPE_TEXT_XML:
                requestBodyParameters.putAll(parseXmlRequestBody(body.toString()));
                break;
            case CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED:
                requestBodyParameters.putAll(queryParamKeyValueGenerator(body.toString(),new HashMap<>()));
                break;
            default:
                break;
        }
        return requestBodyParameters;

    }

    private static Map<String,? extends Set<String>> parseXmlRequestBody(String body) throws RestrictionModeException {
        //write logic to xml parsing
        Map<String, Set<String>> requestBodyParameters = new HashMap<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(body)));
            document.getDocumentElement().normalize();
            Element root = document.getDocumentElement();
            parseXmlNode(root, StringUtils.EMPTY, requestBodyParameters);
        } catch (Exception e) {
            logger.log(LogLevel.FINER, String.format("JSON Request Body parsing failed for %s : reason %s", body, e.getMessage()), RestrictionUtility.class.getName());
            throw new RestrictionModeException(String.format("XML Request Body parsing failed : reason %s", e.getMessage()), e);
        }
        return requestBodyParameters;
    }

    private static void parseXmlNode(Node node, String baseKey, Map<String, Set<String>> requestBodyParameters) {
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element element = (Element) node;
            NodeList children = element.getChildNodes();
            String key = baseKey.isEmpty() ? element.getTagName() : baseKey + "." + element.getTagName();
            if (children.getLength() == 1 && children.item(0).getNodeType() == Node.TEXT_NODE) {
                String value = children.item(0).getTextContent().trim();
                if (!value.isEmpty()) {
                    requestBodyParameters.computeIfAbsent(key, k -> new HashSet<>()).add(value);
                }
            } else {
                for (int i = 0; i < children.getLength(); i++) {
                    parseXmlNode(children.item(i), key, requestBodyParameters);
                }
            }
        }
    }

    private static Map<String,? extends Set<String>> parseJsonRequestBody(String body) throws RestrictionModeException {
        JsonNode node;
        ObjectMapper mapper = new ObjectMapper();
        try {
            node = mapper.readValue(body, JsonNode.class);
            Map<String, Set<String>> requestBodyParameters = new HashMap<>();
            return parseJsonNode(node, StringUtils.EMPTY, requestBodyParameters);
        } catch (JsonProcessingException e) {
            logger.log(LogLevel.FINER, String.format("JSON Request Body parsing failed for %s : reason %s", body, e.getMessage()), RestrictionUtility.class.getName());
            throw new RestrictionModeException(String.format("JSON Request Body parsing failed : reason %s", e.getMessage())+ e.getMessage(), e);
        }
    }

    private static Map<String, Set<String>> parseJsonNode(JsonNode node, String baseKey, Map<String, Set<String>> requestBodyParameters) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> iterator = node.fields();
            while (iterator.hasNext()) {
                Map.Entry<String, JsonNode> entry = iterator.next();
                String key = entry.getKey();
                String base = getBase(baseKey, key);
                JsonNode value = entry.getValue();
                if(value.isContainerNode()){
                    parseJsonNode(value, base, requestBodyParameters);
                } else if (StringUtils.isNotBlank(value.asText())) {
                    if(!requestBodyParameters.containsKey(base)){
                        requestBodyParameters.put(base, new HashSet<>());
                    }
                    requestBodyParameters.get(base).add(value.asText());
                }
            }
        } else if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode jsonNode = arrayNode.get(i);
                String base = getBase(baseKey, i);
                if(jsonNode.isContainerNode()){
                    parseJsonNode(jsonNode, base, requestBodyParameters);
                } else if (StringUtils.isNotBlank(jsonNode.asText())) {
                    if(!requestBodyParameters.containsKey(base)){
                        requestBodyParameters.put(base, new HashSet<>());
                    }
                    requestBodyParameters.get(base).add(jsonNode.asText());
                }
            }
        }
        return requestBodyParameters;
    }

    private static String getBase(String baseKey, String key) {
        if(StringUtils.isBlank(baseKey)){
            return key;
        }
        return baseKey + "." + key;
    }

    private static String getBase(String baseKey, int index) {
        if(StringUtils.isBlank(baseKey)){
            return "[]";
        }
        return String.format("%s[]", baseKey);
    }

    private static Map<String, Set<String>> parseRequestHeaders(Map<String, String> headers) {
        Map<String, Set<String>> requestHeaderParameters = new HashMap<>();
        for (Map.Entry<String, String> header : headers.entrySet()) {
            String key = header.getKey();
            String value = header.getValue();
            putHeaderParameter(key, value, requestHeaderParameters);
            if (StringUtils.containsAny(value, SEPARATOR_CHARS_SEMICOLON, EQUAL)) {
                String[] headerKeyValues = value.split(SEPARATOR_CHARS_SEMICOLON);
                for (int i = 0; i < headerKeyValues.length; i++) {
                    if (StringUtils.contains(headerKeyValues[i], EQUAL)
                            && !StringUtils.endsWith(headerKeyValues[i], EQUAL)) {
                        String headerKey = StringUtils.substringBefore(headerKeyValues[i], EQUAL).trim();
                        String headerValue = StringUtils.substringAfter(headerKeyValues[i], EQUAL).trim();
                        putHeaderParameter(key, headerKey, headerValue, requestHeaderParameters);
                    } else {
                        putHeaderParameter(key, headerKeyValues[i], requestHeaderParameters);
                    }
                }
            }
        }
        return requestHeaderParameters;
    }

    private static void putHeaderParameter(String baseKey, String headerKey, String headerValue, Map<String, Set<String>> requestHeaderParameters) {
        if(StringUtils.isBlank(baseKey)){
            putHeaderParameter(headerKey, headerValue, requestHeaderParameters);
        }
        putHeaderParameter(String.format("%s.%s", baseKey, headerKey), headerValue, requestHeaderParameters);
    }

    private static void putHeaderParameter(String key, String value, Map<String, Set<String>> requestHeaderParameters) {
        Set<String> headerValues = requestHeaderParameters.get(key);
        if (headerValues == null) {
            headerValues = new HashSet<>();
        }
        headerValues.add(StringUtils.lowerCase(value));
        headerValues.add(StringUtils.lowerCase(ServletHelper.urlDecode(value)));
        requestHeaderParameters.put(StringUtils.lowerCase(key), headerValues);
    }

    private static Map<String, Set<String>> parseQueryParameters(String url) {
        Map<String, Set<String>> queryParameters = new HashMap<>();
        String query = StringUtils.substringAfter(url, SEPARATOR_CHARS_QUESTION_MARK);
        if (StringUtils.isNotBlank(query)) {
            queryParamKeyValueGenerator(query, queryParameters);
        } else {
            query = StringUtils.substringAfter(url, SEPARATOR_CHARS_SEMICOLON);
            if (StringUtils.isNotBlank(query)) {
                queryParamKeyValueGenerator(query, queryParameters);
            }
        }
        return queryParameters;
    }

    private static Map<String, Set<String>> queryParamKeyValueGenerator(String query, Map<String, Set<String>> queryParameters) {
        String[] queryParams = StringUtils.split(query, AND);
        for (String queryParam : queryParams) {
            String key, value;
            key = StringUtils.substringBefore(queryParam, SEPARATOR_EQUALS);
            value = StringUtils.substringAfter(queryParam, SEPARATOR_EQUALS);
            Set<String> values = new HashSet<>();
            values.add(StringUtils.lowerCase(value));
            values.add(StringUtils.lowerCase(ServletHelper.urlDecode(value)));
            queryParameters.put(StringUtils.lowerCase(key), values);
        }
        return queryParameters;
    }

    private static Set<String> parsePathParameters(String uri) {
        Set<String> pathParameters = new HashSet<>();
        String requestPath = StringUtils.substringBefore(uri,
                SEPARATOR_CHARS_SEMICOLON);
        if(StringUtils.isNotBlank(requestPath)) {
            String[] pathVariables = StringUtils.split(requestPath, FORWARD_SLASH);
            for (String pathVariable : pathVariables) {
                pathParameters.add(StringUtils.lowerCase(pathVariable));
                pathParameters.add(StringUtils.lowerCase(ServletHelper.urlDecode(pathVariable)));
            }
        }
        return pathParameters;
    }
}
