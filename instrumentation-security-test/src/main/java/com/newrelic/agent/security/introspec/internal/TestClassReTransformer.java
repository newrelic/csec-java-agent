package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.Agent;
import com.newrelic.agent.deps.org.objectweb.asm.ClassReader;
import com.newrelic.agent.deps.org.objectweb.asm.ClassVisitor;
import com.newrelic.agent.deps.org.objectweb.asm.ClassWriter;
import com.newrelic.agent.deps.org.objectweb.asm.commons.Method;
import com.newrelic.agent.instrumentation.classmatchers.ScalaTraitMatcher;
import com.newrelic.agent.instrumentation.context.InstrumentationContext;
import com.newrelic.agent.instrumentation.custom.ScalaTraitFinalFieldVisitor;
import com.newrelic.agent.instrumentation.tracing.NoticeSqlVisitor;
import com.newrelic.agent.instrumentation.tracing.TraceClassVisitor;
import com.newrelic.agent.instrumentation.weaver.ClassWeaverService;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.util.asm.PatchedClassWriter;
import com.newrelic.weave.utils.ClassCache;
import com.newrelic.weave.utils.ClassLoaderFinder;
import com.newrelic.weave.utils.WeaveUtils;
import com.newrelic.weave.weavepackage.ClassWeavedListener;
import com.newrelic.weave.weavepackage.NewClassAppender;
import com.newrelic.weave.weavepackage.PackageWeaveResult;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;

public class TestClassReTransformer implements ClassFileTransformer {

    protected byte[] weave(ClassLoader loader, ClassCache classCache, String className,
                           byte[] classBytes,
                           Map<Method, Collection<String>> skipMethods,
                           ClassWeavedListener listener) throws IOException {
        if (loader == null) {
            return SecurityInstrumentationTestRunner.weavePackageManager.weave(SecurityInstrumentationTestRunner.instrumentingClassloader, classCache, className.replace('.', '/'), classBytes, skipMethods,
                    listener);
        } else {
            return SecurityInstrumentationTestRunner.weavePackageManager.weave(loader, classCache, className.replace('.', '/'), classBytes, skipMethods,
                    listener);
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        try {
            ClassCache classCache = new ClassCache(new ClassLoaderFinder(SecurityInstrumentationTestRunner.instrumentingClassloader));
            ;
            byte[] classBytes = classfileBuffer;
            if (classBytes == null) {
                return null;
            }

            final InstrumentationContext context = new InstrumentationContext(classBytes, classBeingRedefined, protectionDomain);
            new ClassReader(classBytes).accept(new ScalaTraitMatcher().newClassMatchVisitor(loader, classBeingRedefined, null, null, context)
                    , ClassReader.SKIP_FRAMES);
            // weave
            byte[] weaved = weave(loader, classCache, className, classBytes, context.getSkipMethods(), new ClassWeavedListener() {
                @Override
                public void classWeaved(PackageWeaveResult weaveResult, ClassLoader classloader, ClassCache cache) {
                    if (weaveResult.weavedClass()) {
                        final String packageName = weaveResult.getValidationResult().getWeavePackage().getName();
                        for (String originalName : weaveResult.getWeavedMethods().keySet()) {
                            for (Method method : weaveResult.getWeavedMethods().get(originalName)) {
                                context.addWeavedMethod(method, packageName);
                            }
                            ClassWeaverService.addTraceInformation(
                                    SecurityInstrumentationTestRunner.tracedWeaveInstrumentationDetails, packageName, context,
                                    weaveResult.getComposite(), originalName);
                        }

                        try {
                            Map<String, byte[]> annotationProxyClasses = weaveResult.getAnnotationProxyClasses();
                            if (!annotationProxyClasses.isEmpty()) {
                                // Special case for annotation weaving in order to support dynamic annotation proxies. We
                                // need to add the dynamic proxy classes that we created to the current classloader here
                                NewClassAppender.appendClasses(classloader, annotationProxyClasses);
                            }
                        } catch (Exception e) {
                            Agent.LOG.log(Level.FINE, e, "Unable to add annotation proxy classes");
                        }
                    }
                }
            });

            // trace
            if (weaved != null) {
                classBytes = weaved;
            }

            if (classBytes != null && context.isModified() && !context.getScalaFinalFields().isEmpty()) {
                ClassReader reader = new ClassReader(classBytes);
                ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                ClassVisitor cv = writer;
                cv = new ScalaTraitFinalFieldVisitor(cv, context.getScalaFinalFields());
                reader.accept(cv, ClassReader.SKIP_FRAMES);
                classBytes = writer.toByteArray();
            }

            ClassReader reader = new ClassReader(classBytes);
            if (weaved == null) {
                // process trace annotations for non-weaved code
                reader.accept(new InstrumentingClassLoader.SimpleTraceMatchVisitor(null, context), ClassReader.EXPAND_FRAMES);
            }

            if (!context.isTracerMatch()) {
                if (weaved != null) {
                    return classBytes;
                }
                return null;
            }
            NoticeSqlVisitor noticeSqlVisitor = new NoticeSqlVisitor(WeaveUtils.ASM_API_LEVEL);
            reader.accept(noticeSqlVisitor, ClassReader.SKIP_FRAMES); // find the noticeSql calls

            String internalClassName = className.replace('.', '/');
            ClassWriter writer = new PatchedClassWriter(ClassWriter.COMPUTE_FRAMES, context.getClassResolver(SecurityInstrumentationTestRunner.instrumentingClassloader));
            ClassVisitor cv = writer;
            cv = new TraceClassVisitor(cv, internalClassName, context, noticeSqlVisitor.getNoticeSqlMethods());
            cv = new ClassVisitor(WeaveUtils.ASM_API_LEVEL, cv) {
                @Override
                public void visit(int version, int access, String name, String signature, String superName,
                                  String[] interfaces) {
                    if (version < 49 || version > 100) { // Some weird Apache classes have really large versions.
                        version = WeaveUtils.RUNTIME_MAX_SUPPORTED_CLASS_VERSION;
                    }
                    super.visit(version, access, name, signature, superName, interfaces);
                }
            };
            reader.accept(cv, ClassReader.EXPAND_FRAMES);

            byte[] result = writer.toByteArray();

            //printRaw(writer);
            //printClass(className, result);

            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
