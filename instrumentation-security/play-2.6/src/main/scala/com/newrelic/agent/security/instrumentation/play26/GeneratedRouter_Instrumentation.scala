package com.newrelic.agent.security.instrumentation.play26

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper
import com.newrelic.api.agent.security.schema.ApplicationURLMapping
import com.newrelic.api.agent.weaver.{MatchType, Weave, Weaver}
import play.api.routing.HandlerDef
import play.core.routing.{HandlerInvoker, HandlerInvokerFactory}

import scala.collection.JavaConverters.asJavaIterableConverter

@Weave(originalName = "play.core.routing.GeneratedRouter", `type` = MatchType.BaseClass)
abstract class GeneratedRouter_Instrumentation {

  def documentation: Seq[(String, String, String)]

  def createInvoker[T](fakeCall: => T, handlerDef: HandlerDef)(implicit hif: HandlerInvokerFactory[T]): HandlerInvoker[T] = {
    try {
      Weaver.callOriginal()
    } finally {
      gatherURLMappings()
    }
  }

  private def gatherURLMappings(): Unit = {
    val iterator = documentation.asJava.iterator()
    while (iterator.hasNext){
      val doc = iterator.next
      URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(doc._1, doc._2, doc._3))
    }
  }
}


