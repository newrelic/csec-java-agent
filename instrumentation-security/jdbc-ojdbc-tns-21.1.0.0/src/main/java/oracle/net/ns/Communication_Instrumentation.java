/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package oracle.net.ns;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import oracle.jdbc.driver.DMSFactory;
import org.ietf.jgss.GSSCredential;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.Properties;

@Weave(type = MatchType.Interface, originalName = "oracle.net.ns.Communication")
public abstract class Communication_Instrumentation {
    public void connect(String var1, Properties var2, GSSCredential var3, SSLContext var4, DMSFactory.DMSNoun var5) throws IOException, NetException {
        if (NewRelicSecurity.getAgent().getSecurityMetaData() != null && !NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JDBCVendor.META_CONST_JDBC_VENDOR, JDBCVendor.ORACLE);
        }
        Weaver.callOriginal();
    }
}
