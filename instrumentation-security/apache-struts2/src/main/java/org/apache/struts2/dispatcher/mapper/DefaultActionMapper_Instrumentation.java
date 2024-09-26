package org.apache.struts2.dispatcher.mapper;

import com.newrelic.agent.security.instrumentation.apache.struts2.StrutsHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.opensymphony.xwork2.config.ConfigurationManager;

import javax.servlet.http.HttpServletRequest;

@Weave(originalName = "org.apache.struts2.dispatcher.mapper.ActionMapper", type = MatchType.Interface)
public class DefaultActionMapper_Instrumentation {

    public ActionMapping getMapping(HttpServletRequest request, ConfigurationManager configManager) {
        ActionMapping mapping = Weaver.callOriginal();
        StrutsHelper.setRoute(mapping, configManager);
        return mapping;
    }
}
