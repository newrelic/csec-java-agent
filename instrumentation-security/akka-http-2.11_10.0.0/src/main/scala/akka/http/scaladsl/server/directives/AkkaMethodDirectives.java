package akka.http.scaladsl.server.directives;

/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

import akka.http.scaladsl.server.Directive;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.runtime.BoxedUnit;


@Weave(type = MatchType.ExactClass, originalName = "akka.http.scaladsl.server.directives.MethodDirectives$")
public abstract class AkkaMethodDirectives {

    public Directive<BoxedUnit> delete() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }

        return retData;
    }

    public Directive<BoxedUnit> get() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }

    public Directive<BoxedUnit> head() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }

    public Directive<BoxedUnit> options() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }

    public Directive<BoxedUnit> patch() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }

    public Directive<BoxedUnit> post() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }

    public Directive<BoxedUnit> put() {
        Directive<BoxedUnit> retData = Weaver.callOriginal();
        if(ServletHelper.registerUserLevelCode("akka-http", true)) {
            AkkaHttpUtils.processUserLevelServiceTrace();
        }
        return retData;
    }
}
