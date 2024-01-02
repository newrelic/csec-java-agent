/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.ning.http.client;

import com.newrelic.api.agent.weaver.Weave;

@Weave(originalName = "com.ning.http.client.RequestBuilderBase")
abstract class RequestBuilderBase_Instrumentation {

    @Weave(originalName = "com.ning.http.client.RequestBuilderBase$RequestImpl")
    private abstract static class RequestImpl_Instrumentation {
        private Headers headers;

        // Added this instrumentation to return modifiable headers instead
        public Headers getHeaders() {
            return headers;
        }
    }
}
