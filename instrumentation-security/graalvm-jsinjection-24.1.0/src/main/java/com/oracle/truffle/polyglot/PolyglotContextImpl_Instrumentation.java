package com.oracle.truffle.polyglot;

import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.impl.AbstractPolyglotImpl;

@Weave(originalName = "com.oracle.truffle.polyglot.PolyglotContextImpl")
public abstract class PolyglotContextImpl_Instrumentation {

    abstract AbstractPolyglotImpl.APIAccess getAPIAccess();

    public Object eval(String languageId, Object source) {
        Object result;
        try {
            if (source instanceof Source) {
                ((Source) source).getCharacters();

                com.oracle.truffle.api.source.Source sourceReceiver = (com.oracle.truffle.api.source.Source) getAPIAccess().getSourceReceiver(source);
                sourceReceiver.getCharacters();
            }
        } catch (Exception e) {
        }
        result = Weaver.callOriginal();
        return result;
    }
}

