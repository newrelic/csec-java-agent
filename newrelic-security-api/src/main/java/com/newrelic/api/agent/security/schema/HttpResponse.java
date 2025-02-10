package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class HttpResponse {

    @JsonIgnore
    public static final int MAX_ALLOWED_RESPONSE_BODY_LENGTH = 500000;

    private Map<String, String> headers;

    private final StringBuilderLimit body;

    private String contentType;

    private int statusCode;

    private boolean dataTruncated;

    public class StringBuilderLimit {

        StringBuilder sb;

        public StringBuilderLimit() {
            sb = new StringBuilder();
        }

        public StringBuilderLimit(StringBuilderLimit sb) {
            this.sb = new StringBuilder(sb.getSb());
        }

        public StringBuilder getSb() {
            return sb;
        }

        public void setSb(StringBuilder sb) {

            this.sb = sb;
        }

        public StringBuilder append(Object obj) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(obj);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(String str) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(str);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(StringBuffer sb) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return this.sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return this.sb.append(sb);
            } else {
                dataTruncated = true;
            }
            return this.sb;
        }

        public StringBuilder append(CharSequence s) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(s);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(CharSequence s, int start, int end) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(s, start, end);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(char[] str) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(str);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(char[] str, int offset, int len) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(str, offset, len);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(boolean b) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(b);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(char c) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(c);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(int i) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(i);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(long lng) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(lng);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(float f) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(f);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        public StringBuilder append(double d) {
            if (NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return sb;
            }
            if(sb.length() < MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
                return sb.append(d);
            } else {
                dataTruncated = true;
            }
            return sb;
        }

        @Override
        public String toString() {
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof StringBuilderLimit) {
                return sb.equals(((StringBuilderLimit) obj).sb);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return sb.hashCode();
        }
    }

    public HttpResponse() {
        this.headers = new ConcurrentHashMap<>();
        this.body = new StringBuilderLimit();
        this.contentType = StringUtils.EMPTY;
        this.dataTruncated = false;
    }

    public HttpResponse(HttpResponse httpResponse) {
        this.headers = new ConcurrentHashMap<>(httpResponse.getHeaders());
        this.body = new StringBuilderLimit(httpResponse.body);
        this.contentType = httpResponse.contentType.trim();
        this.statusCode = httpResponse.statusCode;
        this.dataTruncated = httpResponse.dataTruncated;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public StringBuilderLimit getBody() {
        return this.body;
    }

    public void setBody(StringBuilder body) {
        this.body.setSb(body);
    }

    public String getResponseContentType() {
        return contentType;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String responseContentType) {
        if (StringUtils.isNotBlank(responseContentType)) {
            this.contentType = StringUtils.substringBefore(responseContentType, ";").trim().toLowerCase();
        } else {
            this.contentType = StringUtils.EMPTY;
        }
    }

    public boolean isDataTruncated() {
        return dataTruncated;
    }

    public void setDataTruncated(boolean dataTruncated) {
        this.dataTruncated = dataTruncated;
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(body.sb, contentType);
    }

    public void clean() {
        headers.clear();
        body.sb.setLength(0);
        contentType = StringUtils.EMPTY;
        statusCode = 0;
        dataTruncated = false;
    }
}
