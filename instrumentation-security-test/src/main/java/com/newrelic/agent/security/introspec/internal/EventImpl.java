/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.security.introspec.Event;

import java.util.Map;

class EventImpl implements Event {

    private String eventType;
    private Map<String, Object> attributes;

    public EventImpl(String type, Map<String, Object> atts) {
        eventType = type;
        attributes = atts;
    }

    @Override
    public String getType() {
        return eventType;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

}
