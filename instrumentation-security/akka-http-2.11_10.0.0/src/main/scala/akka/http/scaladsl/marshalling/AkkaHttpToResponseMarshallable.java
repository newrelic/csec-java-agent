/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package akka.http.scaladsl.marshalling;

import akka.http.scaladsl.AkkaResponseHelper;
import akka.http.scaladsl.model.HttpResponse;
import akka.stream.scaladsl.Flow;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "akka.http.scaladsl.marshalling.ToResponseMarshallable")
public abstract class AkkaHttpToResponseMarshallable {

    @NewField
    public Token token;

    public Marshaller<Object, HttpResponse> marshaller() {
        Marshaller<Object, HttpResponse> marshaller = Weaver.callOriginal();
        return marshaller.map(new AkkaResponseHelper());
    }

}
