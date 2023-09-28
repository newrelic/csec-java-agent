/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.apache.catalina.core;

import javax.servlet.DispatcherType;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class ApplicationDispatcher_Instrumentation {

    /**
     * If this is an async dispatch there are no #ServletRequestListener calls, so handle async here.
     * 
     * {@link ServletRequest#getAsyncContext()} throws an #IllegalStateException, and the asyncContext field in #Request
     * is null, so use the #ServletRequest to find the suspended transaction.
     */
    public void dispatch(ServletRequest servletRequest, ServletResponse servletResponse, DispatcherType dispatcherType) {
    }

}
