
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
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import scala.collection.JavaConversions;
import spray.SprayHttpUtils;
import spray.http.HttpEntity;
import spray.http.HttpHeader;
import spray.http.HttpResponse;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.Interface, originalName = "spray.httpx.marshalling.ToResponseMarshallingContext")
public class SprayToResponseMarshallingContext {

    @Trace(async = true)
    public void marshalTo(HttpResponse httpResponse) {
        System.out.println("Response handling!!! : "+httpResponse.status().value());
        boolean isLockAcquired = GenericHelper.acquireLockIfPossible(SprayHttpUtils.getNrSecCustomAttribNameForResponse());
        try {
            if (isLockAcquired && httpResponse.entity().nonEmpty()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(new StringBuilder(httpResponse.entity().data().asString(StandardCharsets.UTF_8)));
                if (httpResponse.entity() instanceof HttpEntity.NonEmpty) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(((HttpEntity.NonEmpty) httpResponse.entity()).contentType().value());
                }
                SprayHttpUtils.postProcessSecurityHook(httpResponse, this.getClass().getName(), "marshalTo");
            }
        } catch (Exception e){
            e.printStackTrace();
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
