package com.k2cybersecurity.instrumentator.utils;

import java.io.File;
import java.util.Map;
import java.util.Map.Entry;

import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

public class CallbackUtils {

	public static void checkForFileIntegrity(Map<String, FileIntegrityBean> fileLocalMap) {
		for(Entry<String, FileIntegrityBean> entry : fileLocalMap.entrySet()) {
			boolean isExists = new File(entry.getKey()).exists();
			if(!entry.getValue().getExists().equals(isExists)) {
				EventDispatcher.dispatch(entry.getValue(), VulnerabilityCaseType.FILE_INTEGRITY);
			}
		}
	}
}
