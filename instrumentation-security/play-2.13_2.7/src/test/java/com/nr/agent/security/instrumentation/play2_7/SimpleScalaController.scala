/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.play2_7

import play.api.mvc._

import javax.inject.Inject
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class SimpleScalaController @Inject()(components: ControllerComponents) extends AbstractController(components) {

  def scalaHello = Action.async {
    Future {
      Ok("Scala says hello world")
    }
  }

}
