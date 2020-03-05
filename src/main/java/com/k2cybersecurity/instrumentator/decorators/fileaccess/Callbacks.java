package com.k2cybersecurity.instrumentator.decorators.fileaccess;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.nio.file.Paths;
import java.time.Instant;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.SOURCE_EXENSIONS;

public class Callbacks {

	public static final String GET_BOOLEAN_ATTRIBUTES = "getBooleanAttributes";

	public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
								 String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (StringUtils
						.isNotBlank(args[0].toString())) {
					FileOperationalBean fileOperationalBean = new FileOperationalBean(args[0].toString(), className,
							sourceString, exectionId, Instant.now().toEpochMilli(), StringUtils.equals(methodName, GET_BOOLEAN_ATTRIBUTES));
					
					FileIntegrityBean fbean = createEntryOfFileIntegrity(args[0].toString(), sourceString, className, methodName, exectionId);
					EventDispatcher.dispatch(fileOperationalBean, fbean, VulnerabilityCaseType.FILE_OPERATION);
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
		
		
	}

	private static String getFileExtension(File file) {
		String fileName = file.getName();
		if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
			return fileName.substring(fileName.lastIndexOf(".") + 1);
		else
			return StringUtils.EMPTY;
	}
	
	private static FileIntegrityBean createEntryOfFileIntegrity(String fileName, String sourceString, String className, String methodName, String exectionId) {
		File file = Paths.get(fileName).toFile();
		String extension = getFileExtension(file);
		if (SOURCE_EXENSIONS.contains(extension)) {
			FileIntegrityBean fbean = new FileIntegrityBean(file.exists(), fileName, className,
					sourceString, exectionId, Instant.now().toEpochMilli());
			ThreadLocalExecutionMap.getInstance().getFileLocalMap().put(fileName,
					fbean);
			return fbean;
		}
		return null;
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
//		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - return : " + returnVal + " - eid : " + exectionId);
//
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {

//		if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}

	}
}
