/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet;

import com.newrelic.api.agent.weaver.SkipIfPresent;

@SkipIfPresent(originalName = "jakarta.servlet.ServletConnection")
public abstract class ServletConnection {
    // This class is new in 6.0, and we annotate it to prevent 5.0 to be applied to 6.x series
}