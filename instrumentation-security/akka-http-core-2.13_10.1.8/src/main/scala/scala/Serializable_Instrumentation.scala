package scala

import com.newrelic.api.agent.weaver.SkipIfPresent

@SkipIfPresent(originalName = "scala.Serializable")
class Serializable_Instrumentation {

}
