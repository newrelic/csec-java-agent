/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package jakarta.servlet.jsp;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Weave(type = MatchType.Interface)
public class HttpJspPage {
    @NewField
    private String LIBRARY_NAME = "jsp";

    public void _jspService(HttpServletRequest request, HttpServletResponse response) {
        ServletHelper.registerUserLevelCode(LIBRARY_NAME);
        Weaver.callOriginal();
    }
}
