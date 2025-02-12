package com.newrelic.api.agent.security.schema;

import com.newrelic.api.agent.security.schema.annotations.JsonIgnore;
import com.newrelic.api.agent.security.schema.annotations.JsonProperty;

import java.io.Serializable;

public class StringBuilderLimit {

    @JsonIgnore
    public static final int MAX_ALLOWED_BODY_LENGTH = 500000;

    StringBuilder sb;

    @JsonIgnore
    private boolean dataTruncated;

    public StringBuilderLimit() {
        sb = new StringBuilder();
        dataTruncated = false;
    }

    public StringBuilder append(Object obj) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(obj);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(String str) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(str);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(StringBuffer sb) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return this.sb.append(sb);
        } else {
            dataTruncated = true;
        }
        return this.sb;
    }

    public StringBuilder append(CharSequence s) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(s);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(CharSequence s, int start, int end) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(s, start, end);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(char[] str) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(str);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(char[] str, int offset, int len) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(str, offset, len);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(boolean b) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(b);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(char c) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(c);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(int i) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(i);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(long lng) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(lng);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(float f) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(f);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public StringBuilder append(double d) {
        if(sb.length() < MAX_ALLOWED_BODY_LENGTH) {
            return sb.append(d);
        } else {
            dataTruncated = true;
        }
        return sb;
    }

    public void clean() {
        sb = new StringBuilder();
        sb.setLength(0);
        dataTruncated = false;
    }

    @Override
    public String toString() {
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof StringBuilderLimit) {
            return StringUtils.equals(sb, ((StringBuilderLimit) obj).sb);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return sb.hashCode();
    }

    public boolean isDataTruncated() {
        return dataTruncated;
    }

    public void setDataTruncated(boolean dataTruncated) {
        this.dataTruncated = dataTruncated;
    }
}
