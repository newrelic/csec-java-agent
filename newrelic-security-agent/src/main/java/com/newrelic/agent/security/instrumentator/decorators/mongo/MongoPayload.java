package com.newrelic.agent.security.instrumentator.decorators.mongo;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Class to generate and maintain a MongoPayload structure
 */
class MongoPayload {

    static Parser parser;
    private Object payload;
    private String payloadType = MongoConstants.UNKNOWN_PAYLOAD_TYPE;

    static class Parser {
        JSONParser parser;

        /**
         * Initiates the JSONParser
         */
        Parser() {
            parser = new JSONParser();
        }

        /**
         * Parses the bson object into 'relaxed' JSON.
         *
         * @param payload
         * @return
         * @throws ParseException
         * @throws NoSuchMethodException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        Object ParseBSONPayload(Object payload) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, ParseException {
            Method toJson = payload.getClass().getMethod(MongoConstants.BSON_DOCUMENT_TO_JSON_METHOD_NAME);
            toJson.setAccessible(true);
            String jsonString = (String) toJson.invoke(payload);
            return parser.parse(jsonString);
        }

        /**
         * Parses the bson object list into list of 'relaxed' JSONArray.
         *
         * @param payload
         * @return
         * @throws ParseException
         * @throws NoSuchMethodException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        Object ParseBSONPayload(List<Object> payload) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, ParseException {
            JSONArray list = new JSONArray();
            Object item = null;
            Iterator itr = payload.iterator();
            while (itr.hasNext()) {
                item = itr.next();
                list.add(ParseBSONPayload(item));
            }
            return list;
        }

        /**
         * Responsible to generate payload from streaming payload
         * parameter to Mongo's `CommandMessage` constructor.
         *
         * @param args
         * @param streamingPayloadIndex
         * @return
         * @throws Exception
         */
        MongoPayload formDataFromStreamingPayload(Object[] args, final int streamingPayloadIndex) throws Exception {
            if (streamingPayloadIndex > 0 && args[streamingPayloadIndex] != null) {
                Method getPayload = args[streamingPayloadIndex].getClass().getMethod("getPayload");
                getPayload.setAccessible(true);
                List<Object> payload = (List<Object>) getPayload.invoke(args[streamingPayloadIndex]);
                Method getPayloadName = args[streamingPayloadIndex].getClass().getMethod("getPayloadName");
                getPayloadName.setAccessible(true);
                String payloadName = (String) getPayloadName.invoke(args[streamingPayloadIndex]);
                MongoPayload data = new MongoPayload(ParseBSONPayload(payload), payloadName);
                return data;
            }
            return null;
        }

        /**
         * Responsible to generate payload from command
         * parameter to Mongo's `CommandMessage` constructor.
         *
         * @param args
         * @return
         * @throws Exception
         */
        MongoPayload formDataFromCommand(Object[] args) throws Exception {
            MongoPayload data = new MongoPayload(ParseBSONPayload(args[1]));
            Method getKeySet = args[1].getClass().getMethod(MongoConstants.LIST_KEY_SET_METHOD_NAME);
            getKeySet.setAccessible(true);
            Set<String> keys = (Set<String>) getKeySet.invoke(args[1]);
            for (String op : MongoConstants.MONGO_OPERATIONS) {
                if (keys.contains(op)) {
                    data.setPayloadType(op);
                    break;
                }
            }
            return data;
        }

        /**
         * Generates a MongoPayload instance using passed info.
         *
         * @param args
         * @param streamingPayloadIndex
         * @return
         * @throws Exception
         */
        MongoPayload generateMongoPayload(Object[] args, final int streamingPayloadIndex) throws Exception {
            MongoPayload data = formDataFromStreamingPayload(args, streamingPayloadIndex);
            if (data == null) {
                data = formDataFromCommand(args);
            }
            return data;
        }
    }

    /**
     * returns a singleton BSONPayloadParser object
     *
     * @return Parser
     * @throws Exception
     */
    static Parser getParser() throws Exception {
        if (parser == null) {
            parser = new Parser();
        }
        return parser;
    }

    /**
     * Initiates MongoPayload object with just payload
     *
     * @param payload
     */
    MongoPayload(final Object payload) {
        this.payload = payload;
    }

    /**
     * Initiates MongoPayload object with payload and payloadType
     *
     * @param payload
     * @param payloadType
     */
    MongoPayload(final Object payload, final String payloadType) {
        this.payload = payload;
        this.payloadType = payloadType;
    }

    /**
     * Setter for payload
     *
     * @param payload
     */
    public void setPayload(final Object payload) {
        this.payload = payload;
    }

    /**
     * setter for payloadType
     *
     * @param payloadType
     */
    public void setPayloadType(final String payloadType) {
        this.payloadType = payloadType;
    }

    /**
     * Converts the MongoPayload POJO to JSONObject
     *
     * @return
     * @throws Exception
     */
    public JSONObject getJSON() throws Exception {
        JSONObject obj = new JSONObject();
        obj.put(MongoConstants.PAYLOAD_HOLDER, this.payload);
        obj.put(MongoConstants.PAYLOAD_TYPE_HOLDER, this.payloadType);
        return obj;
    }
}
