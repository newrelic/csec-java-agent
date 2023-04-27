/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.instrumentation.security.okhttp35.internal.http;

import com.newrelic.api.agent.weaver.SkipIfPresent;

@SkipIfPresent(originalName = "okhttp3.internal.http.ExchangeCodec")
public abstract class ExchangeCodec_Instrumentation {
}
