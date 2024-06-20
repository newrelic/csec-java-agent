/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.play2_13

import com.newrelic.api.agent.security.NewRelicSecurity
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper
import com.newrelic.api.agent.security.utils.logging.LogLevel
import com.newrelic.api.agent.weaver.{MatchType, Weave, Weaver}
import play.api.mvc.Handler
import play.api.routing.HandlerDef
import play.core.routing.HandlerInvoker


@Weave(`type` = MatchType.Interface, originalName = "play.core.routing.HandlerInvokerFactory")
class HandlerInvokerFactory[T] {
  def createInvoker(fakeCall: => T, handlerDef: HandlerDef): HandlerInvoker[T] = {
    new NewRelicWrapperInvoker(Weaver.callOriginal(), handlerDef)
  }
}

class NewRelicWrapperInvoker[A](underlyingInvoker: HandlerInvoker[A], handlerDef: HandlerDef) extends HandlerInvoker[A] {
  def call(call: => A): Handler = {
    try {
      if (NewRelicSecurity.isHookProcessingActive) {
        val stackTraceElement = new StackTraceElement(handlerDef.controller, handlerDef.method, null , -1)
        val securityMetaData = NewRelicSecurity.getAgent.getSecurityMetaData
        securityMetaData.addCustomAttribute(GenericHelper.USER_CLASS_ENTITY, stackTraceElement)
        securityMetaData.getMetaData.setUserLevelServiceMethodEncountered(true)
      }
    } catch {
      case t: Throwable => NewRelicSecurity.getAgent.log(LogLevel.FINEST, String.format(GenericHelper.ERROR_WHILE_DETECTING_USER_CLASS, "PLAY-2.13_2.7"), t, this.getClass.getName)
    }
    underlyingInvoker.call(call)
  }
}
