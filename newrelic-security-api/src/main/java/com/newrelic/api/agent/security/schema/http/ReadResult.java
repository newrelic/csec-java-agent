/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security.schema.http;

public class ReadResult {
    private final int statusCode;
    private final String responseBody;

    ReadResult(int statusCode, String responseBody) {
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public static ReadResult create(int statusCode, String responseBody) {
        return new ReadResult(statusCode, responseBody);
    }

}
