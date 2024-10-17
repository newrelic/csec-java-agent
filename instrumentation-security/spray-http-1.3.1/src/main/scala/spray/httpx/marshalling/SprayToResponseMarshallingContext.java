
/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package spray.httpx.marshalling;

import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import spray.SprayHttpUtils;
import spray.http.HttpEntity;
import spray.http.HttpResponse;
import java.nio.charset.StandardCharsets;

@Weave(type = MatchType.Interface, originalName = "spray.httpx.marshalling.ToResponseMarshallingContext")
public class SprayToResponseMarshallingContext {

    @Trace(async = true)
    public void marshalTo(HttpResponse httpResponse) {
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, SprayHttpUtils.getNrSecCustomAttribNameForResponse());
        try {
            if (isLockAcquired && httpResponse.entity().nonEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setBody(new StringBuilder(httpResponse.entity().data().asString(StandardCharsets.UTF_8)));
                if (httpResponse.entity() instanceof HttpEntity.NonEmpty) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType(((HttpEntity.NonEmpty) httpResponse.entity()).contentType().value());
                }
                SprayHttpUtils.processResponseHeaders(httpResponse.headers(), NewRelicSecurity.getAgent().getSecurityMetaData().getResponse());
                SprayHttpUtils.postProcessSecurityHook(httpResponse, this.getClass().getName(), "marshalTo");
            }
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_PARSING_HTTP_RESPONSE, SprayHttpUtils.SPRAY_HTTP_1_3_1, e.getMessage()), e, this.getClass().getName());
        }
        try {
             Weaver.callOriginal();
        } finally {
             if(isLockAcquired){
                 GenericHelper.releaseLock(SprayHttpUtils.getNrSecCustomAttribNameForResponse());
             }
        }
    }

}
