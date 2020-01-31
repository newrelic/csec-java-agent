package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

public class ClassLoadListener implements AgentBuilder.Listener {
	@Override
	public void onError(
			final String typeName,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded,
			final Throwable throwable) {
	}

	@Override
	public void onTransformation(
			final TypeDescription typeDescription,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded,
			final DynamicType dynamicType) {
		AgentUtils.getInstance().getTransformedClasses().add(typeDescription.getName());
	}

	@Override
	public void onIgnored(
			final TypeDescription typeDescription,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded) {
		//      log.debug("onIgnored {}", typeDescription.getName());
	}

	@Override
	public void onComplete(
			final String typeName,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded) {
		//      log.debug("onComplete {}", typeName);
	}

	@Override
	public void onDiscovery(
			final String typeName,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded) {
		//      log.debug("onDiscovery {}", typeName);
	}
}