package com.newrelic.api.agent.security.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static com.newrelic.api.agent.security.schema.StringUtils.EMPTY;

public class SSRFUtilsTest {

    @Test
    public void generateTracingHeaderValue() {
        String previousVal = "prev", executionId = "executionId_"+ UUID.randomUUID();
        String apiId = "apiId_"+ UUID.randomUUID(), appUUID = "appUUID"+  UUID.randomUUID();
        Assertions.assertEquals(String.format("%s/%s/%s;", appUUID, apiId, executionId), SSRFUtils.generateTracingHeaderValue(EMPTY, apiId, executionId, appUUID));
        Assertions.assertEquals(String.format("%s;%s/%s/%s;", previousVal, appUUID, apiId, executionId), SSRFUtils.generateTracingHeaderValue(previousVal, apiId, executionId, appUUID));
    }
}
