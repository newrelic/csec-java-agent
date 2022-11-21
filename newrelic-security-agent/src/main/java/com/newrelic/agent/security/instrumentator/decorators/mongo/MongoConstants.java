package com.newrelic.agent.security.instrumentator.decorators.mongo;

import java.util.HashMap;
import java.util.Map;

public interface MongoConstants {
    // This is an exhaustive list of operation types
    // we would be able to identify on from command arg
    String[] MONGO_OPERATIONS = {
            "aggregate",
            "count",
            "createIndexes",
            "distinct",
            "drop",
            "dropIndexes",
            "find",
            "inline",
            "mapreduce",
            "parallelCollectionScan"
    };

    Map<String, String> MONGO_OPERATION_MAP = new HashMap<String, String>() {{
        put(UNKNOWN_PAYLOAD_TYPE, UNKNOWN_PAYLOAD_TYPE);
        put("documents", "insert");
        put("updates", "update");
        put("deletes", "delete");
        put("aggregate", "aggregate");
        put("count", "count");
        put("createIndexes", "createIndexes");
        put("distinct", "distinct");
        put("drop", "drop");
        put("dropIndexes", "dropIndexes");
        put("find", "find");
        put("inline", "inline");
        put("mapreduce", "mapreduce");
        put("parallelCollectionScan", "parallelCollectionScan");
    }};

    String PAYLOAD_HOLDER = "payload";
    String PAYLOAD_TYPE_HOLDER = "payloadType";

    String JSON_WRITER_SETTINGS_CLASS_NAME = "org.bson.json.JsonWriterSettings";
    String JSON_MODE_CLASS_NAME = "org.bson.json.JsonMode";

    String JSON_MODE_VALUE_OF_METHOD_NAME = "valueOf";
    String JSON_MODE_OUTPUT_MODE_RELAXED = "RELAXED";
    String JSON_WRITER_SETTINGS_BUILDER_METHOD_NAME = "builder";
    String JSON_WRITER_SETTINGS_OUTPUT_MODE_METHOD_NAME = "outputMode";
    String JSON_WRITER_SETTINGS_BUILD_METHOD_NAME = "build";
    String BSON_DOCUMENT_TO_JSON_METHOD_NAME = "toJson";
    String LIST_KEY_SET_METHOD_NAME = "keySet";
    String UNKNOWN_PAYLOAD_TYPE = "Unknown";
}
