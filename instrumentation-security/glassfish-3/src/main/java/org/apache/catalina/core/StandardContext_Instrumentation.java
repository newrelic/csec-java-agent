/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.catalina.core;

import java.util.EventListener;

import com.newrelic.agent.security.instrumentation.glassfish3.TomcatServletRequestListener;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.catalina.core.StandardContext")
public abstract class StandardContext_Instrumentation {

    protected void contextListenerStart() {

        try {
            addListener(new TomcatServletRequestListener());
            System.out.println(String.format("Registered ServletRequestListener for %s : %s", this.getClass(), getPath()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        Weaver.callOriginal();

    }

    public abstract String getPath();

    public abstract void addListener(EventListener listener);
}
