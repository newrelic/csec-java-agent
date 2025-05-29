package com.newrelic.agent.security.instrumentator.helper;

import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.AttributeValueUpdate;
import software.amazon.awssdk.services.dynamodb.model.ExpectedAttributeValue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import static com.newrelic.api.agent.security.schema.operation.DynamoDBOperation.Category.*;

public class DynamoDBRequestConverterTest {
    public final String PARAMETERS = "parameters";
    private final String PAYLOAD = "payload";
    private final String QUERY = "query";
    private final String PAYLOAD_TYPE = "payloadType";
    private final String OP = "operation";
    private final String EXPRESSION = "#col = :val";
    private final String TABLE = "test";
    private final String stringVal = "value";
    private final String STMT = "select * from test;";
    private final DynamoDBRequest REQUEST =  new DynamoDBRequest(null, OP);
    @Test(expected = RuntimeException.class)
    public void Convert0Test(){
        DynamoDBRequestConverter.convert(DQL, REQUEST);
    }
    @Test
    public void Convert1Test(){
        REQUEST.setQuery(new DynamoDBRequest.Query());
        REQUEST.setQueryType(null);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertNull(obj.get(PAYLOAD_TYPE));
        Assert.assertEquals("{}", obj.get(PAYLOAD).toString());
    }
    @Test
    public void Convert2Test(){
        REQUEST.setQuery(new DynamoDBRequest.Query());
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));
        Assert.assertEquals("{}", obj.get(PAYLOAD).toString());
    }
    @Test
    public void Convert3Test(){
        REQUEST.setQuery(new DynamoDBRequest.Query());
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));
        Assert.assertEquals("{}", obj.get(PAYLOAD).toString());
    }

    @Test
    public void PartiQLTest(){
        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setStatement(STMT);
        query.setParameters(new Object());
        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(PARTIQL, REQUEST);
        Assert.assertEquals(STMT, obj.get(QUERY));
    }
    @Test
    public void PartiQL1Test(){
        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setStatement(STMT);

        query.setParameters(Collections.singletonList(ExpectedAttributeValue.builder().value(AttributeValue.builder().s(stringVal).build()).build()));
        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(PARTIQL, REQUEST);
        Assert.assertEquals(STMT, obj.get(QUERY));

        Object[] some = ((Object[])(obj.get(PARAMETERS)));
        Assert.assertTrue(some[0] instanceof JSONObject);
        Assert.assertEquals(stringVal, ((JSONObject)(some[0])).get("s"));
    }
    @Test
    public void PartiQL2Test(){
        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setStatement(STMT);

        query.setParameters(Collections.singletonList(AttributeValue.builder().s(stringVal).build()));
        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(PARTIQL, REQUEST);
        Assert.assertEquals(STMT, obj.get(QUERY));

        Object[] some = ((Object[])(obj.get(PARAMETERS)));
        Assert.assertTrue(some[0] instanceof JSONObject);
        Assert.assertEquals(stringVal, ((JSONObject)(some[0])).get("s"));
    }
    @Test
    public void PartiQL3Test(){
        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setStatement(STMT);

        query.setParameters(Collections.singletonList(AttributeValueUpdate.builder().value(AttributeValue.builder().s(stringVal).build()).build()));
        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(PARTIQL, REQUEST);
        Assert.assertEquals(STMT, obj.get(QUERY));

        Object[] some = ((Object[])(obj.get(PARAMETERS)));
        Assert.assertTrue(some[0] instanceof JSONObject);
        Assert.assertEquals(stringVal, ((JSONObject)(some[0])).get("s"));
    }

    @Test
    public void ConvertKeyExTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        ArrayList<Object> list = new ArrayList<>();
        list.add(map);

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setKey(list);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("key"));
        Assert.assertEquals(list, new ArrayList<>(Arrays.asList((Object[]) payload.get("key"))));
    }
    @Test
    public void ConvertItemExTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setItem(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("item"));
        Assert.assertEquals(map, payload.get("item"));
    }
    @Test
    public void ConvertExAttNamesTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setExpressionAttributeNames(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("expressionAttributeNames"));
        Assert.assertEquals(map, payload.get("expressionAttributeNames"));
    }
    @Test
    public void ConvertExAttValuesTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setExpressionAttributeValues(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("expressionAttributeValues"));
        Assert.assertEquals(map, payload.get("expressionAttributeValues"));
    }
    @Test
    public void ConvertAttToGetTest(){
        ArrayList<String> list1 = new ArrayList<>();
        list1.add("col1");
        list1.add("col2");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setAttributesToGet(list1);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("attributesToGet"));
        Assert.assertEquals(list1, payload.get("attributesToGet"));
    }
    @Test
    public void ConvertScanFilterTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setScanFilter(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("scanFilter"));
        Assert.assertEquals(map, payload.get("scanFilter"));
    }
    @Test
    public void ConvertQueryFilterTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setQueryFilter(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("queryFilter"));
        Assert.assertEquals(map, payload.get("queryFilter"));
    }
    @Test
    public void ConvertExpectedTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setExpected(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("expected"));
        Assert.assertEquals(map, payload.get("expected"));
    }
    @Test
    public void ConvertAttUpdatesTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");
        map.put("key1", "val1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setAttributeUpdates(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("attributeUpdates"));
        Assert.assertEquals(map, payload.get("attributeUpdates"));
    }

    @Test
    public void ConvertParametersTest(){
        ArrayList<String> list1 = new ArrayList<>();
        list1.add("val1");
        list1.add("val2");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setParameters(list1);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));

        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get(PARAMETERS));
        Assert.assertEquals(list1, new ArrayList<>(Arrays.asList((Object[]) payload.get(PARAMETERS))));
    }
    @Test
    public void ConvertAllTest(){
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "val");

        ArrayList<String> list1 = new ArrayList<>();
        list1.add("col1");

        DynamoDBRequest.Query query = new DynamoDBRequest.Query();
        query.setKey(map);
        query.setItem(list1);
        query.setTableName(TABLE);
        query.setConditionExpression(EXPRESSION);
        query.setKeyConditionExpression(EXPRESSION);
        query.setFilterExpression(EXPRESSION);
        query.setUpdateExpression(EXPRESSION);
        query.setProjectionExpression(EXPRESSION);
        query.setExpressionAttributeNames(map);
        query.setExpressionAttributeValues(map);
        query.setAttributesToGet(list1);
        query.setQueryFilter(map);
        query.setScanFilter(map);
        query.setExpected(list1);
        query.setAttributeUpdates(map);
        query.setStatement(STMT);
        query.setParameters(map);

        REQUEST.setQuery(query);
        JSONObject obj = DynamoDBRequestConverter.convert(DQL, REQUEST);
        Assert.assertEquals(OP, obj.get(PAYLOAD_TYPE));


        JSONObject payload = (JSONObject) obj.get(PAYLOAD);
        Assert.assertNotNull(payload);

        Assert.assertNotNull(payload.get("key"));
        Assert.assertEquals(map, payload.get("key"));

        Assert.assertNotNull(payload.get("item"));
        Assert.assertEquals(list1, new ArrayList<>(Arrays.asList(((Object[]) payload.get("item")))));

        Assert.assertNotNull(payload.get("tableName"));
        Assert.assertEquals(TABLE, payload.get("tableName"));

        Assert.assertNotNull(payload.get("conditionExpression"));
        Assert.assertEquals(EXPRESSION, payload.get("conditionExpression"));

        Assert.assertNotNull(payload.get("keyConditionExpression"));
        Assert.assertEquals(EXPRESSION, payload.get("keyConditionExpression"));

        Assert.assertNotNull(payload.get("filterExpression"));
        Assert.assertEquals(EXPRESSION, payload.get("filterExpression"));

        Assert.assertNotNull(payload.get("updateExpression"));
        Assert.assertEquals(EXPRESSION, payload.get("updateExpression"));

        Assert.assertNotNull(payload.get("projectionExpression"));
        Assert.assertEquals(EXPRESSION, payload.get("projectionExpression"));

        Assert.assertNotNull(payload.get("expressionAttributeNames"));
        Assert.assertEquals(map, payload.get("expressionAttributeNames"));

        Assert.assertNotNull(payload.get("expressionAttributeValues"));
        Assert.assertEquals(map, payload.get("expressionAttributeValues"));

        Assert.assertNotNull(payload.get("attributesToGet"));
        Assert.assertEquals(list1, payload.get("attributesToGet"));

        Assert.assertNotNull(payload.get("queryFilter"));
        Assert.assertEquals(map, payload.get("queryFilter"));

        Assert.assertNotNull(payload.get("scanFilter"));
        Assert.assertEquals(map, payload.get("scanFilter"));

        Assert.assertNotNull(payload.get("expected"));
        Assert.assertEquals(list1, new ArrayList<>(Arrays.asList(((Object[]) payload.get("expected")))));

        Assert.assertNotNull(payload.get("statement"));
        Assert.assertEquals(STMT, payload.get("statement"));

        Assert.assertNotNull(payload.get("attributeUpdates"));
        Assert.assertEquals(map, payload.get("attributeUpdates"));

        Assert.assertNotNull(payload.get(PARAMETERS));
        Assert.assertEquals(map, payload.get(PARAMETERS));
    }

}
