package com.k2cybersecurity.instrumentator.dispatcher;

import java.time.Instant;
import java.util.List;

import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

public class DispatchUtils {

	public static void dispatchAll(List<JavaAgentEventBean> list, HttpRequestBean httpRequestBean, String tid) {
		DispatcherPool.getInstance().getLazyEvents().remove(tid);
		for(JavaAgentEventBean newEventBean : list) {
			newEventBean.setHttpRequest(httpRequestBean);
			newEventBean.setEventGenerationTime(Instant.now().toEpochMilli());
			EventSendPool.getInstance().sendEvent(newEventBean.toString());
			System.out.println("============= Event Start ============");
			System.out.println(newEventBean);
			System.out.println("============= Event End ============");
		}
	}
	
}
