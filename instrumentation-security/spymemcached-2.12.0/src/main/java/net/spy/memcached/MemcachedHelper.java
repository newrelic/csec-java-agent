package net.spy.memcached;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.MemcachedOperation;
import net.spy.memcached.ops.CASOperation;
import net.spy.memcached.ops.ConcatenationOperation;
import net.spy.memcached.ops.Operation;
import net.spy.memcached.ops.StoreOperation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class MemcachedHelper {
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "MEMCACHED_OPERATION_LOCK_";
}
