package com.nr.instrumentation.security.javaio;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;

public class IOStreamHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME_READER = "NR_SEC_CUSTOM_ATTRIB_NAME_READER";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM = "NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM";

    private static final String REQUEST_READER_HASH = "REQUEST_READER_HASH";

    private static final String RESPONSE_WRITER_HASH = "RESPONSE_WRITER_HASH";
    private static final String RESPONSE_OUTPUTSTREAM_HASH = "RESPONSE_OUTPUTSTREAM_HASH";

    public static final String LF = "\n";


    public static Boolean processRequestReaderHookData(Integer readerHash) {
        try {
            if(NewRelicSecurity.isHookProcessingActive() && NewRelicSecurity.getAgent().getSecurityMetaData()!= null) {
                return readerHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(REQUEST_READER_HASH, Integer.class));
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static Boolean processResponseWriterHookData(Integer writerHash) {
        return writerHash.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_WRITER_HASH, Integer.class));
    }

    public static Boolean processResponseOutputStreamHookData(Integer outputStreamHash) {
        try {
            Integer x = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(RESPONSE_OUTPUTSTREAM_HASH, Integer.class);
            return outputStreamHash.equals(x);
        } catch (Throwable ignored) {}
        return false;
    }

    public static void preprocessSecurityHook(byte[] dataBuffer,
                                        int offset, int writeDataLength) {
        try {
            if (writeDataLength > -1) {
                char[] data = new char[writeDataLength];
                for (int i = offset, y = 0; i < offset + writeDataLength; i++, y++) {
                    data[y] = (char) dataBuffer[i];
                }
//                        System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseBody().append(data);
            }
        } catch(Throwable ignored) {}
    }

    public static boolean acquireLockIfPossible(int hashCode) {
        try {
            if(IOStreamHelper.processResponseOutputStreamHookData(hashCode)) {
                return GenericHelper.acquireLockIfPossible(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM, hashCode);
            }
        } catch (Throwable ignored) {}
        return false;
    }

    public static void releaseLock(int hashCode) {
        try {
            GenericHelper.releaseLock(IOStreamHelper.NR_SEC_CUSTOM_ATTRIB_NAME_OUTPUT_STREAM, hashCode);
        } catch (Throwable ignored) {}
    }
}
