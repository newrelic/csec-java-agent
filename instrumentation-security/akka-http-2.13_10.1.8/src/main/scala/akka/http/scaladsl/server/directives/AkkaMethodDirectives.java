/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl.server.directives;

import akka.http.scaladsl.server.Directive;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.runtime.BoxedUnit;


@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.server.directives.MethodDirectives$")
public abstract class AkkaMethodDirectives {

    public Directive<BoxedUnit> post() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }
}
