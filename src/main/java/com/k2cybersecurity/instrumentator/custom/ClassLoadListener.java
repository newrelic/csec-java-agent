package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Arrays;

public class ClassLoadListener implements AgentBuilder.Listener {
	@Override
	public void onError(
			final String typeName,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded,
			final Throwable throwable) {
//		System.out.println(String.format("Transformation error : class : %s :: error %s", typeName,
//				Arrays.asList(throwable.getStackTrace())));

	}

	@Override
	public void onTransformation(
			final TypeDescription typeDescription,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded,
			final DynamicType dynamicType) {
		AgentUtils.getInstance().getTransformedClasses().add(Pair.of(typeDescription.getName(), classLoader));
		AgentUtils.getInstance().createProtectedVulnerabilties(typeDescription, classLoader);
//		System.out.println("Transformed class : " + typeDescription.getName());
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
		try {
			AgentUtils.getInstance().putClassloaderRecord(typeName, classLoader);
		} catch (Throwable e){
//			System.out.println("Error while registering classloader : " + typeName + " : " + classLoader + " : " + e.getMessage() + " : " + e.getCause());
		}
		AgentUtils.getInstance().addProtectedVulnerabilties(typeName);
	}

	@Override
	public void onDiscovery(
			final String typeName,
			final ClassLoader classLoader,
			final JavaModule module,
			final boolean loaded) {
		//      log.debug("onDiscovery {}", typeName);
//		System.out.println("Discovered class : " + typeName);

	}
}