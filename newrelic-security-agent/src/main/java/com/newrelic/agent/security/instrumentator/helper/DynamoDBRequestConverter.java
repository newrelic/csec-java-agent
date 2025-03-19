package com.newrelic.agent.security.instrumentator.helper;

import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.json.simple.JSONObject;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DynamoDBRequestConverter {
    public static final String UNABLE_TO_PARSE_DYNAMO_DB_REQUEST = "Unable to parse DynamoDB request: %s";
    private static List<String> allowedFields = Arrays.asList("s","n","b","ss","ns","bs","m","l");
    public static JSONObject convert(DynamoDBOperation.Category category, DynamoDBRequest request) {
        JSONObject json = new JSONObject();
        if (category==DynamoDBOperation.Category.DQL) {
            json.put("payloadType", request.getQueryType());
            try {
                json.put("payload", convertQuery(request.getQuery()));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                Agent.getInstance().reportIncident(LogLevel.WARNING, String.format(UNABLE_TO_PARSE_DYNAMO_DB_REQUEST, JsonConverter.toJSON(request)), e, DynamoDBRequestConverter.class.getName());
            }
        }
        else if (category==DynamoDBOperation.Category.PARTIQL) {
            json.put("query", request.getQuery().getStatement());
            try {
                json.put("parameters", convertAttributeValue(request.getQuery().getParameters()));
            } catch (NoSuchFieldException | IllegalAccessException e) {
                Agent.getInstance().reportIncident(LogLevel.WARNING, String.format(UNABLE_TO_PARSE_DYNAMO_DB_REQUEST, JsonConverter.toJSON(request)), e, DynamoDBRequestConverter.class.getName());
            }
        }
        return json;
    }

    private static JSONObject convertQuery(DynamoDBRequest.Query query) throws NoSuchFieldException, IllegalAccessException {
        JSONObject json = new JSONObject();
        if (query.getKey() != null) {
            json.put("key", convertAttributeValue(query.getKey()));
        }
        if (query.getItem() != null) {
            json.put("item", convertAttributeValue(query.getItem()));
        }
        if (query.getTableName() != null) {
            json.put("tableName", query.getTableName());
        }
        if (query.getConditionExpression() != null) {
            json.put("conditionExpression", query.getConditionExpression());
        }
        if (query.getKeyConditionExpression() != null) {
            json.put("keyConditionExpression", query.getKeyConditionExpression());
        }
        if (query.getFilterExpression() != null) {
            json.put("filterExpression", query.getFilterExpression());
        }
        if (query.getUpdateExpression() != null) {
            json.put("updateExpression", query.getUpdateExpression());
        }
        if (query.getProjectionExpression() != null) {
            json.put("projectionExpression", query.getProjectionExpression());
        }
        if (query.getExpressionAttributeNames() != null) {
            json.put("expressionAttributeNames", query.getExpressionAttributeNames());
        }
        if (query.getExpressionAttributeValues() != null) {
            json.put("expressionAttributeValues", convertAttributeValue(query.getExpressionAttributeValues()));
        }
        if (query.getAttributesToGet() != null) {
            json.put("attributesToGet", query.getAttributesToGet());
        }
        if (query.getQueryFilter() != null) {
            json.put("queryFilter", convertAttributeValue(query.getQueryFilter()));
        }
        if (query.getScanFilter() != null) {
            json.put("scanFilter", convertAttributeValue(query.getScanFilter()));
        }
        if (query.getExpected() != null) {
            json.put("expected", convertAttributeValue(query.getExpected()));
        }
        if (query.getAttributeUpdates() != null) {
            json.put("attributeUpdates", convertAttributeValue(query.getAttributeUpdates()));
        }
        if (query.getStatement() != null) {
            json.put("statement", query.getStatement());
        }
        if (query.getParameters() != null) {
            json.put("parameters", convertAttributeValue(query.getParameters()));
        }
        return json;
    }

    private static Object convertAttributeValue(Object value) throws NoSuchFieldException, IllegalAccessException {
        if (value instanceof Map) {
            JSONObject json = new JSONObject();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                json.put(entry.getKey().toString(), convertAttributeValue(entry.getValue()));
            }
            return json;
        } else if (value instanceof List) {
            List<?> list = (List<?>) value;
            Object[] array = new Object[list.size()];
            for (int i = 0; i < list.size(); i++) {
                array[i] = convertAttributeValue(list.get(i));
            }
            return array;
        }
        else if (value.getClass().getName().contains("AttributeValueUpdate") || value.getClass().getName().contains("ExpectedAttributeValue")) {
            Field field = value.getClass().getDeclaredField("value");
            field.setAccessible(true);
            return convertAttributeValue(field.get(value));
        }
        else if (value.getClass().getName().contains("AttributeValue")) {
            Map<String, Object> map = new HashMap<>();
            Field[] fields = value.getClass().getDeclaredFields();
            for (Field field : fields) {
                if (allowedFields.contains(field.getName())) {
                    field.setAccessible(true);
                    try {
                        Object o = field.get(value);
                        if(o != null) {
                            if (!((o instanceof List && ((List) o).size() == 0) || (o instanceof Map && ((Map) o).size() == 0))) {
                                map.put(field.getName(), o);
                            }
                        }
                    } catch (IllegalAccessException ignored) {
                        if (Agent.isDebugEnabled()) {
                            NewRelicSecurity.getAgent().log(LogLevel.FINEST, "Debug: Error occurred while sending the event.", ignored, CallbackUtils.class.getName());
                        }
                    }
                }
            }
            return new JSONObject(map);
        }
        else {
            return value;
        }
    }
}
