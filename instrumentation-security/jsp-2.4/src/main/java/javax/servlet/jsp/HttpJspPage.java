/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package javax.servlet.jsp;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Weave(type = MatchType.Interface)
public class HttpJspPage {

    public void _jspService(HttpServletRequest request, HttpServletResponse response) {
        preprocessSecurityHook();
        Weaver.callOriginal();
    }

    private void preprocessSecurityHook() {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered()) {
                securityMetaData.getMetaData().setUserLevelServiceMethodEncountered(true);
                securityMetaData.getMetaData().setServiceTrace(Thread.currentThread().getStackTrace());
            }
        } catch (Throwable ignored) {}
    }
}
