package com.k2cybersecurity.instrumentator;

import org.apache.commons.lang3.StringUtils;

import java.util.*;

public class Hooks {

	public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

	public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

	public static Set<String> ANNOTATION_BASED_HOOKS = new HashSet<>();

	public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

	public static Set<String> IAST_BASED_HOOKS = new HashSet<String>();

	static {

		/**
		 * ------------------------------------ Hooks
		 * ------------------------------------------------
		 **/

		// HTTP request hooks
		TYPE_BASED_HOOKS.put("javax.servlet.Servlet", Arrays.asList("service"));
		TYPE_BASED_HOOKS.put("javax.servlet.jsp.HttpJspPage", Arrays.asList("_jspService"));

		TYPE_BASED_HOOKS.put("javax.servlet.ServletInputStream", Arrays.asList("read", "readLine"));
		TYPE_BASED_HOOKS.put("javax.servlet.ServletOutputStream", Arrays.asList("print", "write", "println"));

		TYPE_BASED_HOOKS.put("java.io.PrintWriter",
				Arrays.asList("write", "newLine", "format", "println", "print", "printf", "append"));
		TYPE_BASED_HOOKS.put("java.io.BufferedReader", Arrays.asList("read", "readLine"));

		TYPE_BASED_HOOKS.put("javax.servlet.ServletRequest", Arrays.asList("getInputStream", "getReader", null));
		TYPE_BASED_HOOKS.put("javax.servlet.ServletResponse", Arrays.asList("getOutputStream", "getWriter", null));
		TYPE_BASED_HOOKS.put("javax.servlet.Filter", Collections.singletonList("doFilter"));
		TYPE_BASED_HOOKS.put("javax.servlet.FilterChain", Collections.singletonList("doFilter"));

		// Web Framework Based hooks

		// Spring MVC
		ANNOTATION_BASED_HOOKS.add("org.springframework.web.bind.annotation.Mapping");

		// Jersey
		ANNOTATION_BASED_HOOKS.add("javax.ws.rs.Path");
		ANNOTATION_BASED_HOOKS.add("javax.ws.rs.HttpMethod");


		// SQL hooks
		TYPE_BASED_HOOKS.put("java.sql.Statement", Arrays.asList("execute", "executeBatch", "executeLargeBatch",
				"executeLargeUpdate", "executeQuery", "executeUpdate"));
		TYPE_BASED_HOOKS.put("java.sql.PreparedStatement",
				Arrays.asList("execute", "executeBatch", "executeLargeBatch", "executeLargeUpdate", "executeQuery",
						"executeUpdate", "setNull", "setBoolean", "setByte", "setShort", "setInt", "setLong",
						"setFloat", "setDouble", "setBigDecimal", "setString", "setBytes", "setDate", "setTime",
						"setTimestamp", "setAsciiStream", "setUnicodeStream", "setBinaryStream", "setObject",
						"setCharacterStream", "setRef", "setBlob", "setClob", "setArray", "setURL", "setRowId",
						"setNString", "setNCharacterStream", "setNClob", "setSQLXML"));

		// Probably these are not needed as CallableStatement implements
		// PreparedStatement
//		TYPE_BASED_HOOKS.put("java.sql.CallableStatement",
//				Arrays.asList("execute", "executeBatch", "executeLargeBatch", "executeLargeUpdate", "executeQuery",
//						"executeUpdate", "setNull", "setBoolean", "setByte", "setShort", "setInt", "setLong",
//						"setFloat", "setDouble", "setBigDecimal", "setString", "setBytes", "setDate", "setTime",
//						"setTimestamp", "setAsciiStream", "setUnicodeStream", "setBinaryStream", "setObject",
//						"setCharacterStream", "setRef", "setBlob", "setClob", "setArray", "setURL", "setRowId",
//						"setNString", "setNCharacterStream", "setNClob", "setSQLXML"));

		TYPE_BASED_HOOKS.put("java.sql.Connection", Arrays.asList("nativeSQL", "prepareCall", "prepareStatement"));

		// LDAP Java Lib
		TYPE_BASED_HOOKS.put("javax.naming.directory.DirContext", Collections.singletonList("search"));
		// LDAP Unbounded Lib
		TYPE_BASED_HOOKS.put("com.unboundid.ldap.sdk.LDAPInterface", Collections.singletonList("search"));
		// LDAP Apache Lib
		NAME_BASED_HOOKS.put("org.apache.directory.server.core.DefaultOperationManager",
				Collections.singletonList("search"));
		// LDAP Spring framework LdapTemplate uses LDAP Java Lib internally, therefore
		// no extra hook required.
		// LDAP ldaptive lib 2.x
		NAME_BASED_HOOKS.put("org.ldaptive.SearchRequest", Collections.singletonList("setFilter"));
		NAME_BASED_HOOKS.put("org.ldaptive.SearchOperation", Collections.singletonList("execute"));
		// LDAP ldaptive lib 1.x uses DirContext
		// LDAP OpenDJ lib
		TYPE_BASED_HOOKS.put("org.forgerock.opendj.ldap.Connection", Collections.singletonList("searchAsync"));

		// trust boundary hooks
		TYPE_BASED_HOOKS.put("javax.servlet.http.HttpSession", Arrays.asList("setAttribute", "putValue"));

		// Secure Cookie
		TYPE_BASED_HOOKS.put("javax.servlet.http.HttpServletResponse", Collections.singletonList("addCookie"));

		// Forkexec hooks
		NAME_BASED_HOOKS.put("java.lang.ProcessImpl", Arrays.asList("start"));

		//System Exit hooks
		NAME_BASED_HOOKS.put("java.lang.Shutdown", Arrays.asList(new String[]{"exit", "halt"}));

		// File Hooks
		NAME_BASED_HOOKS.put("java.io.FileOutputStream", Arrays.asList("open"));
		NAME_BASED_HOOKS.put("java.io.FileInputStream", Arrays.asList("open"));
		NAME_BASED_HOOKS.put("sun.nio.fs.UnixNativeDispatcher", Arrays.asList(new String[]{"open", "fopen", "link",
				"unlink", "mknod", "rename", "mkdir", "rmdir", "symlink", "chown", "chmod"}));
		NAME_BASED_HOOKS.put("java.io.UnixFileSystem", Collections.singletonList("delete"));
		NAME_BASED_HOOKS.put("java.io.File", Collections.singletonList("list"));
		NAME_BASED_HOOKS.put("java.io.RandomAccessFile", Collections.singletonList("open"));
		TYPE_BASED_HOOKS.put("java.io.FileSystem", Collections.singletonList("getBooleanAttributes"));

		// Mongo Hooks
		NAME_BASED_HOOKS.put("com.mongodb.connection.CommandMessage", Collections.singletonList(null));

		NAME_BASED_HOOKS.put("com.mongodb.internal.connection.CommandMessage", Collections.singletonList(null));


		// Weak Random
		NAME_BASED_HOOKS.put("java.util.Random", Arrays.asList(new String[]{"nextBytes", "nextInt", "nextLong",
				"nextBoolean", "nextFloat", "nextDouble", "nextGaussian"}));
		NAME_BASED_HOOKS.put("java.lang.Math", Collections.singletonList("random"));

		// Strong random
		NAME_BASED_HOOKS.put("java.security.SecureRandom", Arrays.asList(new String[]{"nextBytes", "nextInt",
				"nextLong", "nextBoolean", "nextFloat", "nextDouble", "nextGaussian"}));

		// Jetty Servlet Hooks
		TYPE_BASED_HOOKS.put("org.eclipse.jetty.server.Handler", Collections.singletonList("handle"));

		// XPath
		NAME_BASED_HOOKS.put("org.apache.xpath.XPath", Collections.singletonList("execute"));
		NAME_BASED_HOOKS.put("com.sun.org.apache.xpath.internal.XPath", Collections.singletonList("execute"));
		// XPath Dom4jParser
		NAME_BASED_HOOKS.put("org.jaxen.saxpath.base.XPathReader", Collections.singletonList("parse"));
		NAME_BASED_HOOKS.put("net.sf.saxon.sxpath.XPathExpression", Collections.singletonList("iterate"));
		// XPath Saxon
		//NAME_BASED_HOOKS.put("net.sf.saxon.s9api.XPathCompiler", Collections.singletonList("compile"));
		//NAME_BASED_HOOKS.put("net.sf.saxon.expr.parser.ExpressionTool", Collections.singletonList("make"));
		NAME_BASED_HOOKS.put("net.sf.saxon.xpath.XPathEvaluator", Collections.singletonList("compile"));
		NAME_BASED_HOOKS.put("net.sf.saxon.sxpath.XPathEvaluator", Collections.singletonList("createExpression"));
//		NAME_BASED_HOOKS.put("net.sf.saxon.style.UseWhenFilter", Arrays.asList("evaluateStatic", "evaluateUseWhen"));
//		NAME_BASED_HOOKS.put("net.sf.saxon.style.StyleElement", Collections.singletonList("makeExpression"));
		// XPath VTDXML
		NAME_BASED_HOOKS.put("com.ximpleware.AutoPilot", Arrays.asList("declareVariableExpr", "evalXPath", "evalXPathToBoolean", "evalXPathToNumber", "evalXPathToString", "selectXPath"));
		
		// XQuery standard
		NAME_BASED_HOOKS.put("net.sf.saxon.query.StaticQueryContext", Collections.singletonList("compileQuery"));
		NAME_BASED_HOOKS.put("com.saxonica.xqj.SaxonXQPreparedExpression", Collections.singletonList("executeQuery"));
		// XQuery eXist lib
		TYPE_BASED_HOOKS.put("org.xmldb.api.modules.XQueryService", Arrays.asList("query", "queryResource", "compile", "execute"));
		// XQuery Oracle XQJ
		NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQCConnection", Collections.singletonList("prepareExpressionImpl"));
		NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQCPreparedExpression", Collections.singletonList("executeQuery"));
		NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression", Arrays.asList("executeQuery", null));
		NAME_BASED_HOOKS.put("oracle.xml.xquery.compiler.parser.antlr.runtime.ANTLRReaderStream", Collections.singletonList("load"));
		// XQuery brackit
		NAME_BASED_HOOKS.put("org.brackit.xquery.XQuery", Arrays.asList(null, "run"));
		
//		//NAME_BASED_HOOKS.put("net.xqj.basex.bin.G", Collections.singletonList("executeQuery"));
//		TYPE_BASED_HOOKS.put("javax.xml.xquery.XQExpression", Arrays.asList("executeQuery"));
//		TYPE_BASED_HOOKS.put("javax.xml.xquery.XQConnection", Arrays.asList("prepareExpression", "createExpression"));
//		//Zorba
		NAME_BASED_HOOKS.put("io.zorba.api.Zorba", Collections.singletonList("compileQuery"));
		NAME_BASED_HOOKS.put("io.zorba.api.XQuery", Arrays.asList("iterator", "compile", "execute"));

		// JBoss Classloading Hook
//		NAME_BASED_HOOKS.put("org.jboss.modules.Main", Collections.singletonList("main"));

		// OSGi Classloading Hook
		NAME_BASED_HOOKS.put("org.osgi.framework.Bundle", Arrays.asList("start", "update"));

		// SSRF Hook
		NAME_BASED_HOOKS.put("akka.http.scaladsl.HttpExt", Arrays.asList("singleRequest", "singleRequestImpl"));

		TYPE_BASED_HOOKS.put("org.apache.http.client.HttpClient", Collections.singletonList("execute"));
		TYPE_BASED_HOOKS.put("org.apache.http.nio.client.HttpAsyncClient", Collections.singletonList("execute"));
		TYPE_BASED_HOOKS.put("org.apache.http.nio.protocol.HttpAsyncRequestProducer", Collections.singletonList("generateRequest"));
		NAME_BASED_HOOKS.put("org.apache.commons.httpclient.HttpClient", Collections.singletonList("executeMethod"));
		NAME_BASED_HOOKS.put("com.google.api.client.http.HttpRequest", Arrays.asList("execute", "executeAsync"));
		TYPE_BASED_HOOKS.put("java.net.URLConnection", Collections.singletonList("connect"));
		NAME_BASED_HOOKS.put(StringUtils.replace("com@squareup@okhttp@Call", "@", "."), Arrays.asList("execute", null));
		NAME_BASED_HOOKS.put(StringUtils.replace("com@squareup@okhttp@Call", "@", ".") + "$AsyncCall", Collections.singletonList("execute"));

		NAME_BASED_HOOKS.put("okhttp3.OkHttpClient", Collections.singletonList("newCall"));
		TYPE_BASED_HOOKS.put("okhttp3.Call", Collections.singletonList("execute"));

		// CRYPTO
		NAME_BASED_HOOKS.put("javax.crypto.Cipher", Collections.singletonList("getInstance"));
		NAME_BASED_HOOKS.put("javax.crypto.KeyGenerator", Collections.singletonList("getInstance"));
		NAME_BASED_HOOKS.put("java.security.KeyPairGenerator", Collections.singletonList("getInstance"));

		// HASH
		NAME_BASED_HOOKS.put("java.security.MessageDigest", Collections.singletonList("getInstance"));

		// NAME_BASED_HOOKS.put(CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT,
		// Collections.singletonList("execute")); // Handle differently

		// JavaScript Injection
		NAME_BASED_HOOKS.put("jdk.nashorn.api.scripting.NashornScriptEngine", Arrays.asList("evalImpl"));
		NAME_BASED_HOOKS.put("com.oracle.truffle.polyglot.PolyglotContextImpl", Collections.singletonList("eval"));
		NAME_BASED_HOOKS.put("org.mozilla.javascript.Context", Collections.singletonList("compileImpl"));
		TYPE_BASED_HOOKS.put("org.mozilla.javascript.Script", Collections.singletonList("exec"));

//		NAME_BASED_HOOKS.put("org.mozilla.javascript.Parser", Collections.singletonList("parse"));
//		TYPE_BASED_HOOKS.put("org.mozilla.javascript.Script", Collections.singletonList("exec"));
		
		
		/**
		 * ------------------------------------ Decorators
		 * ------------------------------------------------
		 **/

		// HTTP request
		DECORATOR_ENTRY.put("javax.servlet.Servlet.service",
				"com.k2cybersecurity.instrumentator.decorators.httpservice");

		DECORATOR_ENTRY.put("javax.servlet.jsp.HttpJspPage._jspService",
				"com.k2cybersecurity.instrumentator.decorators.httpservice");

		DECORATOR_ENTRY.put("javax.servlet.ServletInputStream.read",
				"com.k2cybersecurity.instrumentator.decorators.servletinputstream");
		DECORATOR_ENTRY.put("javax.servlet.ServletInputStream.readLine",
				"com.k2cybersecurity.instrumentator.decorators.servletinputstream");

		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.print",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");
		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.println",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");
		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.write",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");
		
		
		DECORATOR_ENTRY.put("javax.servlet.Filter.doFilter",
				"com.k2cybersecurity.instrumentator.decorators.servletdofilter");
		DECORATOR_ENTRY.put("javax.servlet.FilterChain.doFilter",
				"com.k2cybersecurity.instrumentator.decorators.servletdofilter");
		
		DECORATOR_ENTRY.put("java.io.PrintWriter.write", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.newLine", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.println", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.print", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.printf", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.format", "com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.append", "com.k2cybersecurity.instrumentator.decorators.printwriter");

		DECORATOR_ENTRY.put("java.io.BufferedReader.read",
				"com.k2cybersecurity.instrumentator.decorators.servletreader");
		DECORATOR_ENTRY.put("java.io.BufferedReader.readLine",
				"com.k2cybersecurity.instrumentator.decorators.servletreader");

		DECORATOR_ENTRY.put("javax.servlet.ServletRequest.null",
				"com.k2cybersecurity.instrumentator.decorators.servletrequest");
		DECORATOR_ENTRY.put("javax.servlet.ServletRequest.getReader",
				"com.k2cybersecurity.instrumentator.decorators.servletrequest");
		DECORATOR_ENTRY.put("javax.servlet.ServletRequest.getInputStream",
				"com.k2cybersecurity.instrumentator.decorators.servletrequest");

		DECORATOR_ENTRY.put("javax.servlet.ServletResponse.null",
				"com.k2cybersecurity.instrumentator.decorators.servletresponse");
		DECORATOR_ENTRY.put("javax.servlet.ServletResponse.getWriter",
				"com.k2cybersecurity.instrumentator.decorators.servletresponse");
		DECORATOR_ENTRY.put("javax.servlet.ServletResponse.getOutputStream",
				"com.k2cybersecurity.instrumentator.decorators.servletresponse");

		// Spring MVC
		DECORATOR_ENTRY.put("org.springframework.web.bind.annotation.Mapping",
				"com.k2cybersecurity.instrumentator.decorators.servicetrace");

		// Jersey
		DECORATOR_ENTRY.put("javax.ws.rs.Path",
				"com.k2cybersecurity.instrumentator.decorators.servicetrace");
		DECORATOR_ENTRY.put("javax.ws.rs.HttpMethod",
				"com.k2cybersecurity.instrumentator.decorators.servicetrace");

		// SQL Create
		DECORATOR_ENTRY.put("java.sql.Connection.nativeSQL",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Connection.prepareCall",
				"com.k2cybersecurity.instrumentator.decorators.sqlcreate");
		DECORATOR_ENTRY.put("java.sql.Connection.prepareStatement",
				"com.k2cybersecurity.instrumentator.decorators.sqlcreate");

		// SQL Execute
		DECORATOR_ENTRY.put("java.sql.Statement.execute", "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeLargeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeLargeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeQuery",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.execute",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeLargeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeLargeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeQuery",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.execute",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeLargeBatch",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeLargeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeQuery",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeUpdate",
				"com.k2cybersecurity.instrumentator.decorators.sqlexecute");

		// SQL set args
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNull",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBoolean",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setByte",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setShort",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setInt",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setLong",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setFloat",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setDouble",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBigDecimal",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setString",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBytes",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setDate",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setTime",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setTimestamp",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setAsciiStream",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setUnicodeStream",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBinaryStream",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setObject",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setCharacterStream",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setRef",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBlob",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setClob",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setArray",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setURL",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setRowId",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNString",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNCharacterStream",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNClob",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setSQLXML",
				"com.k2cybersecurity.instrumentator.decorators.sqlargsetter");

		// Forkexec
		DECORATOR_ENTRY.put("java.lang.ProcessImpl.start", "com.k2cybersecurity.instrumentator.decorators.forkexec");
		
		// System exit
		DECORATOR_ENTRY.put("java.lang.Shutdown.exit", "com.k2cybersecurity.instrumentator.decorators.systemexit");
		DECORATOR_ENTRY.put("java.lang.Shutdown.halt", "com.k2cybersecurity.instrumentator.decorators.systemexit");

		// File
		DECORATOR_ENTRY.put("java.io.FileOutputStream.open",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.FileInputStream.open", "com.k2cybersecurity.instrumentator.decorators.fileaccess");

		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.open",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.fopen",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.link",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.unlink",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.mknod",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.rename",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.mkdir",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.rmdir",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.symlink",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.chown",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.chmod",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");

		DECORATOR_ENTRY.put("java.io.UnixFileSystem.delete",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.RandomAccessFile.open",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.File.list", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.FileSystem.getBooleanAttributes",
				"com.k2cybersecurity.instrumentator.decorators.fileaccess");

		// Mongo Execute
		DECORATOR_ENTRY.put("com.mongodb.connection.CommandMessage.null", "com.k2cybersecurity.instrumentator.decorators.mongo");

		DECORATOR_ENTRY.put("com.mongodb.internal.connection.CommandMessage.null", "com.k2cybersecurity.instrumentator.decorators.mongo");

		// LDAP search
		DECORATOR_ENTRY.put("javax.naming.directory.DirContext.search",
				"com.k2cybersecurity.instrumentator.decorators.ldap");
		// LDAP Unbounded Lib
		DECORATOR_ENTRY.put("com.unboundid.ldap.sdk.LDAPInterface.search",
				"com.k2cybersecurity.instrumentator.decorators.ldaplibs");
		// LDAP Unbounded Lib
		DECORATOR_ENTRY.put("org.apache.directory.server.core.DefaultOperationManager.search",
				"com.k2cybersecurity.instrumentator.decorators.ldaplibs");
		// LDAP ldaptive lib 2.x

		DECORATOR_ENTRY.put("org.ldaptive.SearchRequest.setFilter",
				"com.k2cybersecurity.instrumentator.decorators.ldaptivefilter");
		DECORATOR_ENTRY.put("org.ldaptive.SearchOperation.execute",
				"com.k2cybersecurity.instrumentator.decorators.ldaplibs");
		// LDAP OpenDJ lib
		// Although com.forgerock.opendj.ldap.LDAPConnection.searchAsync is the
		// implementation which is called as per the examples executed
		// which could be put into ldaplibs switch case using source string, there are
		// three different implementations which can be called, therefore a separate
		// decorator with Connection interface has been created. each Search internally calls searchAsync
		DECORATOR_ENTRY.put("org.forgerock.opendj.ldap.Connection.searchAsync",
				"com.k2cybersecurity.instrumentator.decorators.opendjldap");

		// XPath execute both packages for java standard

		DECORATOR_ENTRY.put("org.apache.xpath.XPath.execute", "com.k2cybersecurity.instrumentator.decorators.xpath");
		DECORATOR_ENTRY.put("com.sun.org.apache.xpath.internal.XPath.execute",
				"com.k2cybersecurity.instrumentator.decorators.xpath");
		// XPath Dom4jParser
		DECORATOR_ENTRY.put("org.jaxen.saxpath.base.XPathReader.parse", "com.k2cybersecurity.instrumentator.decorators.xpath");
		DECORATOR_ENTRY.put("net.sf.saxon.sxpath.XPathExpression.iterate", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
//		DECORATOR_ENTRY.put("net.sf.saxon.s9api.XPathCompiler.compile", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
//		DECORATOR_ENTRY.put("net.sf.saxon.expr.parser.ExpressionTool.make", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
		DECORATOR_ENTRY.put("net.sf.saxon.xpath.XPathEvaluator.compile", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
		DECORATOR_ENTRY.put("net.sf.saxon.sxpath.XPathEvaluator.createExpression", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
//		DECORATOR_ENTRY.put("net.sf.saxon.style.UseWhenFilter.evaluateStatic", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
//		DECORATOR_ENTRY.put("net.sf.saxon.style.UseWhenFilter.evaluateUseWhen", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
//		DECORATOR_ENTRY.put("net.sf.saxon.style.StyleElement.makeExpression", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
		// XPath VTD-XML
		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.declareVariableExpr", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");
		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.selectXPath", "com.k2cybersecurity.instrumentator.decorators.xpath.saxoncompile");

		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.evalXPath", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.evalXPathToBoolean", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.evalXPathToNumber", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");
		DECORATOR_ENTRY.put("com.ximpleware.AutoPilot.evalXPathToString", "com.k2cybersecurity.instrumentator.decorators.xpath.saxon");

		// XQuery standard
		DECORATOR_ENTRY.put("net.sf.saxon.query.StaticQueryContext.compileQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("com.saxonica.xqj.SaxonXQPreparedExpression.executeQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		// XQuery eXist lib
		DECORATOR_ENTRY.put("org.xmldb.api.modules.XQueryService.query", "com.k2cybersecurity.instrumentator.decorators.xquery");
		DECORATOR_ENTRY.put("org.xmldb.api.modules.XQueryService.queryResource", "com.k2cybersecurity.instrumentator.decorators.xquery");
		DECORATOR_ENTRY.put("org.xmldb.api.modules.XQueryService.compile", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("org.xmldb.api.modules.XQueryService.execute", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		// XQuery Oracle XQJ
//				NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQCConnection", Collections.singletonList("prepareExpressionImpl"));
//				NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression", Collections.singletonList(null));
//				NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQCPreparedExpression", Collections.singletonList("executeQuery"));
//				NAME_BASED_HOOKS.put("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression", Collections.singletonList("executeQuery"));
		DECORATOR_ENTRY.put("oracle.xml.xquery.xqjimpl.OXQCConnection.prepareExpressionImpl", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression.null", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("oracle.xml.xquery.xqjimpl.OXQCPreparedExpression.executeQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		DECORATOR_ENTRY.put("oracle.xml.xquery.xqjimpl.OXQDPreparedExpression.executeQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		NAME_BASED_HOOKS.put("oracle.xml.xquery.compiler.parser.antlr.runtime.ANTLRReaderStream", Collections.singletonList("load"));
		DECORATOR_ENTRY.put("oracle.xml.xquery.compiler.parser.antlr.runtime.ANTLRReaderStream.load", "com.k2cybersecurity.instrumentator.decorators.xquery.loadbuffer");
		// XQuery brackit
//		NAME_BASED_HOOKS.put("org.brackit.xquery.XQuery", Arrays.asList(null, "run"));
		DECORATOR_ENTRY.put("org.brackit.xquery.XQuery.null", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("org.brackit.xquery.XQuery.run", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		//DECORATOR_ENTRY.put("net.xqj.basex.bin.G.executeQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		DECORATOR_ENTRY.put("javax.xml.xquery.XQExpression.executeQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		DECORATOR_ENTRY.put("javax.xml.xquery.XQExpression.null", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		DECORATOR_ENTRY.put("javax.xml.xquery.XQConnection.prepareExpression", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
//		DECORATOR_ENTRY.put("javax.xml.xquery.XQConnection.createExpression", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		//Zorba
		DECORATOR_ENTRY.put("io.zorba.api.Zorba.compileQuery", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("io.zorba.api.XQuery.compile", "com.k2cybersecurity.instrumentator.decorators.xquery.saxoncompile");
		DECORATOR_ENTRY.put("io.zorba.api.XQuery.iterator", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		DECORATOR_ENTRY.put("io.zorba.api.XQuery.execute", "com.k2cybersecurity.instrumentator.decorators.xquery.saxon");
		
		// Jetty Servlet
		DECORATOR_ENTRY.put("org.eclipse.jetty.server.Handler.handle",
				"com.k2cybersecurity.instrumentator.decorators.jettyhandle");

		// JBoss Classloading
		DECORATOR_ENTRY.put("org.jboss.modules.Main.main",
				"com.k2cybersecurity.instrumentator.decorators.jbossadjustments");

		// OSGi Classloading
		DECORATOR_ENTRY.put("org.osgi.framework.Bundle.start",
				"com.k2cybersecurity.instrumentator.decorators.osgiadjustments");
		DECORATOR_ENTRY.put("org.osgi.framework.Bundle.update",
				"com.k2cybersecurity.instrumentator.decorators.osgiadjustments");

		// Weak random
		DECORATOR_ENTRY.put("java.util.Random.nextBytes", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextInt", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextLong", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextBoolean", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextFloat", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextDouble", "com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.util.Random.nextGaussian",
				"com.k2cybersecurity.instrumentator.decorators.weakrandom");
		DECORATOR_ENTRY.put("java.lang.Math.random", "com.k2cybersecurity.instrumentator.decorators.weakrandom");

		// strong random
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextBytes",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextInt",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextLong",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextBoolean",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextFloat",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextDouble",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");
		DECORATOR_ENTRY.put("java.security.SecureRandom.nextGaussian",
				"com.k2cybersecurity.instrumentator.decorators.strongrandom");

		// SSRF
		DECORATOR_ENTRY.put("java.net.URLConnection.connect", "com.k2cybersecurity.instrumentator.decorators.ssrf");

		DECORATOR_ENTRY.put("akka.http.scaladsl.HttpExt.singleRequest", "com.k2cybersecurity.instrumentator.decorators.ssrf.akkahttp10");
		DECORATOR_ENTRY.put("akka.http.scaladsl.HttpExt.singleRequestImpl", "com.k2cybersecurity.instrumentator.decorators.ssrf.akkahttp10");

		DECORATOR_ENTRY.put("org.apache.http.client.HttpClient.execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.apachehttpclient4");
		DECORATOR_ENTRY.put("org.apache.http.nio.client.HttpAsyncClient.execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.apachehttpasyncclient4");
		DECORATOR_ENTRY.put("org.apache.http.nio.protocol.HttpAsyncRequestProducer.generateRequest", "com.k2cybersecurity.instrumentator.decorators.ssrf.apachehttpasyncclient4");

		DECORATOR_ENTRY.put("org.apache.commons.httpclient.HttpClient.executeMethod", "com.k2cybersecurity.instrumentator.decorators.ssrf.commonshttpclient2");
		DECORATOR_ENTRY.put("com.google.api.client.http.HttpRequest.execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.googlehttpclient");
		DECORATOR_ENTRY.put("com.google.api.client.http.HttpRequest.executeAsync", "com.k2cybersecurity.instrumentator.decorators.ssrf.googlehttpclient");

		DECORATOR_ENTRY.put(StringUtils.replace("com@squareup@okhttp@Call", "@", ".") + ".null", "com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp");
		DECORATOR_ENTRY.put(StringUtils.replace("com@squareup@okhttp@Call", "@", ".") + ".execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp");
		DECORATOR_ENTRY.put(StringUtils.replace("com@squareup@okhttp@Call", "@", ".") + "$AsyncCall.execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp");

		DECORATOR_ENTRY.put("okhttp3.OkHttpClient.newCall", "com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp3");
		DECORATOR_ENTRY.put("okhttp3.Call.execute", "com.k2cybersecurity.instrumentator.decorators.ssrf.okhttp3");

		// Secure cookie
		DECORATOR_ENTRY.put("javax.servlet.http.HttpServletResponse.addCookie",
				"com.k2cybersecurity.instrumentator.decorators.securecookie");

		// trust boundary
		DECORATOR_ENTRY.put("javax.servlet.http.HttpSession.setAttribute",
				"com.k2cybersecurity.instrumentator.decorators.trustboundary");
		DECORATOR_ENTRY.put("javax.servlet.http.HttpSession.putValue",
				"com.k2cybersecurity.instrumentator.decorators.trustboundary");

		// CRYPTO
		DECORATOR_ENTRY.put("javax.crypto.Cipher.getInstance", "com.k2cybersecurity.instrumentator.decorators.crypto");
		DECORATOR_ENTRY.put("javax.crypto.KeyGenerator.getInstance",
				"com.k2cybersecurity.instrumentator.decorators.crypto");
		DECORATOR_ENTRY.put("java.security.KeyPairGenerator.getInstance",
				"com.k2cybersecurity.instrumentator.decorators.crypto");

		// HASH
		DECORATOR_ENTRY.put("java.security.MessageDigest.getInstance",
				"com.k2cybersecurity.instrumentator.decorators.hash");
		
		// JavaScript Injection
		DECORATOR_ENTRY.put("jdk.nashorn.api.scripting.NashornScriptEngine.evalImpl", "com.k2cybersecurity.instrumentator.decorators.jsinjection");
		DECORATOR_ENTRY.put("com.oracle.truffle.polyglot.PolyglotContextImpl.eval", "com.k2cybersecurity.instrumentator.decorators.jsinjection");
		DECORATOR_ENTRY.put("org.mozilla.javascript.Context.compileImpl", "com.k2cybersecurity.instrumentator.decorators.jsinjection.rhinoparse");
		DECORATOR_ENTRY.put("org.mozilla.javascript.Script.exec", "com.k2cybersecurity.instrumentator.decorators.jsinjection.rhino");

//		DECORATOR_ENTRY.put("org.mozilla.javascript.Parser.parse", "com.k2cybersecurity.instrumentator.decorators.jsinjection.rhinoparse");
//		DECORATOR_ENTRY.put("org.mozilla.javascript.Script.exec", "com.k2cybersecurity.instrumentator.decorators.jsinjection.rhino");
//		NAME_BASED_HOOKS.put("org.mozilla.javascript.Parser", Collections.singletonList("parse"));
//		TYPE_BASED_HOOKS.put("org.mozilla.javascript.Script", Collections.singletonList("exec"));

		/** ---------------------IAST CASE TYPE ------------------ */

		IAST_BASED_HOOKS.addAll(Arrays.asList("javax.servlet.http.HttpSession",
				"javax.servlet.http.HttpServletResponse", "java.util.Random", "java.lang.Math",
				"java.security.SecureRandom", "javax.crypto.Cipher", "javax.crypto.KeyGenerator",
				"java.security.KeyPairGenerator", "java.security.MessageDigest", "java.io.FileSystem"));

	}
}
