package com.k2cybersecurity.instrumentator;

import java.util.*;

public class Hooks {

	public static Map<String, List<String>> NAME_BASED_HOOKS = new HashMap<>();

	public static Map<String, List<String>> TYPE_BASED_HOOKS = new HashMap<>();

	public static Map<String, String> DECORATOR_ENTRY = new HashMap<>();

	static {

		/** ------------------------------------  Hooks ------------------------------------------------**/

		// HTTP request hooks
		TYPE_BASED_HOOKS.put("javax.servlet.GenericServlet", Arrays.asList("service"));
		TYPE_BASED_HOOKS.put("javax.servlet.ServletInputStream", Arrays.asList("read"));
		TYPE_BASED_HOOKS.put("javax.servlet.ServletOutputStream", Arrays.asList("print", "println", "write"));
		TYPE_BASED_HOOKS.put("java.io.PrintWriter", Arrays.asList("write", "newLine", "format"));

		// SQL hooks
		TYPE_BASED_HOOKS.put("java.sql.Statement",
				Arrays.asList("execute", "executeBatch", "executeLargeBatch", "executeLargeUpdate", "executeQuery",
						"executeUpdate"));
		TYPE_BASED_HOOKS.put("java.sql.PreparedStatement",
				Arrays.asList("execute", "executeBatch", "executeLargeBatch", "executeLargeUpdate", "executeQuery",
						"executeUpdate", "setNull", "setBoolean", "setByte", "setShort", "setInt", "setLong",
						"setFloat", "setDouble", "setBigDecimal", "setString", "setBytes", "setDate", "setTime",
						"setTimestamp", "setAsciiStream", "setUnicodeStream", "setBinaryStream", "setObject",
						"setCharacterStream", "setRef", "setBlob", "setClob", "setArray", "setURL", "setRowId",
						"setNString", "setNCharacterStream", "setNClob", "setSQLXML"));

		// Probably these are not needed as CallableStatement implements PreparedStatement
//		TYPE_BASED_HOOKS.put("java.sql.CallableStatement",
//				Arrays.asList("execute", "executeBatch", "executeLargeBatch", "executeLargeUpdate", "executeQuery",
//						"executeUpdate", "setNull", "setBoolean", "setByte", "setShort", "setInt", "setLong",
//						"setFloat", "setDouble", "setBigDecimal", "setString", "setBytes", "setDate", "setTime",
//						"setTimestamp", "setAsciiStream", "setUnicodeStream", "setBinaryStream", "setObject",
//						"setCharacterStream", "setRef", "setBlob", "setClob", "setArray", "setURL", "setRowId",
//						"setNString", "setNCharacterStream", "setNClob", "setSQLXML"));

		TYPE_BASED_HOOKS.put("java.sql.Connection",
				Arrays.asList("nativeSQL", "prepareCall", "prepareStatement"));
		
		TYPE_BASED_HOOKS.put("javax.naming.directory.DirContext", Collections.singletonList("search"));

		// Forkexec hooks
		NAME_BASED_HOOKS.put("java.lang.ProcessImpl", Arrays.asList("start"));

		// File Hooks
		NAME_BASED_HOOKS.put("java.io.FileOutputStream", Arrays.asList("open"));
		NAME_BASED_HOOKS.put("java.io.FileInputStream", Arrays.asList("open"));
		NAME_BASED_HOOKS.put("sun.nio.fs.UnixNativeDispatcher", Arrays.asList(new String[] {"open", "fopen", "link", "unlink", "mknod", "rename", "mkdir", "rmdir", "symlink", "chown", "chmod"}));
		NAME_BASED_HOOKS.put("java.io.UnixFileSystem", Collections.singletonList("delete"));
		NAME_BASED_HOOKS.put("java.io.RandomAccessFile", Collections.singletonList("open"));

		// Mongo Hooks

		NAME_BASED_HOOKS.put("com.mongodb.connection.DefaultServerConnection", Collections.singletonList("executeProtocol"));
		NAME_BASED_HOOKS.put("com.mongodb.internal.connection.DefaultServerConnection",Collections.singletonList("executeProtocol"));
		NAME_BASED_HOOKS.put("com.mongodb.async.client.MongoClientImpl$2", Collections.singletonList("execute"));
		NAME_BASED_HOOKS.put("com.mongodb.async.client.AsyncOperationExecutorImpl", Collections.singletonList("execute"));
		NAME_BASED_HOOKS.put("com.mongodb.async.client.OperationExecutorImpl", Collections.singletonList("execute"));

		// Jetty Servlet Hooks
		NAME_BASED_HOOKS.put("org.eclipse.jetty.server.Handler", Collections.singletonList("handle"));

		// JBoss Classloading Hook
		NAME_BASED_HOOKS.put("org.jboss.modules.Main", Collections.singletonList("main"));

		// OSGi Classloading Hook
		NAME_BASED_HOOKS.put("org.osgi.framework.Bundle", Arrays.asList("start", "update"));

		// SSRF Hook
		NAME_BASED_HOOKS.put("org.apache.http.protocol.HttpRequestExecutor", Collections.singletonList("doSendRequest"));
		NAME_BASED_HOOKS.put("sun.net.www.protocol.http.Handler", Collections.singletonList("openConnection"));
		NAME_BASED_HOOKS.put("sun.net.www.protocol.https.Handler", Collections.singletonList("openConnection"));
		NAME_BASED_HOOKS.put("com.sun.net.ssl.internal.www.protocol.https.Handler", Collections.singletonList("openConnection"));
		NAME_BASED_HOOKS.put("jdk.incubator.http.MultiExchange", Arrays.asList(new String[] { "response", "responseAsync", "multiResponseAsync" }));
		NAME_BASED_HOOKS.put("org.apache.commons.httpclient.HttpMethodDirector", Collections.singletonList("executeWithRetry"));
		NAME_BASED_HOOKS.put("com.squareup.okhttp.internal.http.HttpEngine", Collections.singletonList("sendRequest"));
		NAME_BASED_HOOKS.put("weblogic.net.http.Handler", Collections.singletonList("openConnection"));

		//		NAME_BASED_HOOKS.put(CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT, Collections.singletonList("execute"));  // Handle differently

		/** ------------------------------------  Decorators ------------------------------------------------**/

		// HTTP request
		DECORATOR_ENTRY.put("javax.servlet.GenericServlet.service",
				"com.k2cybersecurity.instrumentator.decorators.httpservice");
		DECORATOR_ENTRY.put("javax.servlet.ServletInputStream.read",
				"com.k2cybersecurity.instrumentator.decorators.servletinputstream");

		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.print",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");
		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.println",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");
		DECORATOR_ENTRY.put("javax.servlet.ServletOutputStream.write",
				"com.k2cybersecurity.instrumentator.decorators.servletoutputstream");

		DECORATOR_ENTRY.put("java.io.PrintWriter.write",
				"com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.newLine",
				"com.k2cybersecurity.instrumentator.decorators.printwriter");
		DECORATOR_ENTRY.put("java.io.PrintWriter.format",
				"com.k2cybersecurity.instrumentator.decorators.printwriter");

		// SQL Create
		DECORATOR_ENTRY.put("java.sql.Connection.nativeSQL" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Connection.prepareCall" , "com.k2cybersecurity.instrumentator.decorators.sqlcreate");
		DECORATOR_ENTRY.put("java.sql.Connection.prepareStatement" , "com.k2cybersecurity.instrumentator.decorators.sqlcreate");

		// SQL Execute
		DECORATOR_ENTRY.put("java.sql.Statement.execute" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeLargeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeLargeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeQuery" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.Statement.executeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.execute" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeLargeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeLargeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeQuery" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.executeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.execute" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeLargeBatch" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeLargeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeQuery" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");
		DECORATOR_ENTRY.put("java.sql.CallableStatement.executeUpdate" , "com.k2cybersecurity.instrumentator.decorators.sqlexecute");


		// SQL set args
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNull" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBoolean" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setByte" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setShort" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setInt" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setLong" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setFloat" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setDouble" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBigDecimal" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setString" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBytes" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setDate" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setTime" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setTimestamp" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setAsciiStream" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setUnicodeStream" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBinaryStream" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setObject" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setCharacterStream" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setRef" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setBlob" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setClob" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setArray" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setURL" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setRowId" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNString" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNCharacterStream" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setNClob" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");
		DECORATOR_ENTRY.put("java.sql.PreparedStatement.setSQLXML" , "com.k2cybersecurity.instrumentator.decorators.sqlargsetter");


		// Forkexec
		DECORATOR_ENTRY.put("java.lang.ProcessImpl.start", "com.k2cybersecurity.instrumentator.decorators.forkexec");

		// File
		DECORATOR_ENTRY.put("java.io.FileOutputStream.open", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.FileInputStream.open", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher", "com.k2cybersecurity.instrumentator.decorators.fileaccess");

		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.open", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.fopen", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.link", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.unlink", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.mknod", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.rename", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.mkdir", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.rmdir", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.symlink", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.chown", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("sun.nio.fs.UnixNativeDispatcher.chmod", "com.k2cybersecurity.instrumentator.decorators.fileaccess");

		DECORATOR_ENTRY.put("java.io.UnixFileSystem.delete", "com.k2cybersecurity.instrumentator.decorators.fileaccess");
		DECORATOR_ENTRY.put("java.io.RandomAccessFile.open", "com.k2cybersecurity.instrumentator.decorators.fileaccess");

 		// Mongo Execute
		DECORATOR_ENTRY.put("com.mongodb.connection.DefaultServerConnection.executeProtocol", "com.k2cybersecurity.instrumentator.decorators.mongoexecute");
		DECORATOR_ENTRY.put("com.mongodb.internal.connection.DefaultServerConnection.executeProtocol", "com.k2cybersecurity.instrumentator.decorators.mongoexecute");
		DECORATOR_ENTRY.put("com.mongodb.async.client.MongoClientImpl$2.execute", "com.k2cybersecurity.instrumentator.decorators.mongoexecute");
		DECORATOR_ENTRY.put("com.mongodb.async.client.AsyncOperationExecutorImpl.execute", "com.k2cybersecurity.instrumentator.decorators.mongoexecute");
		DECORATOR_ENTRY.put("com.mongodb.async.client.OperationExecutorImpl.execute", "com.k2cybersecurity.instrumentator.decorators.mongoexecute");
		
		
		//LDAP search
		DECORATOR_ENTRY.put("javax.naming.directory.DirContext.search", "com.k2cybersecurity.instrumentator.decorators.ldap");

		// Jetty Servlet
		DECORATOR_ENTRY.put("org.eclipse.jetty.server.Handler.handle", "com.k2cybersecurity.instrumentator.decorators.jettyhandle");

		// JBoss Classloading
		DECORATOR_ENTRY.put("org.jboss.modules.Main.main", "com.k2cybersecurity.instrumentator.decorators.jbossadjustments");

		// OSGi Classloading
		DECORATOR_ENTRY.put("org.osgi.framework.Bundle.start", "com.k2cybersecurity.instrumentator.decorators.osgiadjustments");
		DECORATOR_ENTRY.put("org.osgi.framework.Bundle.update", "com.k2cybersecurity.instrumentator.decorators.osgiadjustments");

		// SSRF
		DECORATOR_ENTRY.put("org.apache.http.protocol.HttpRequestExecutor.doSendRequest", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("sun.net.www.protocol.http.Handler.openConnection", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("sun.net.www.protocol.https.Handler.openConnection", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("com.sun.net.ssl.internal.www.protocol.https.Handler.openConnection", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("jdk.incubator.http.MultiExchange.response", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("jdk.incubator.http.MultiExchange.responseAsync", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("jdk.incubator.http.MultiExchange.multiResponseAsync", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("com.squareup.okhttp.internal.http.HttpEngine.sendRequest", "com.k2cybersecurity.instrumentator.decorators.ssrf");
		DECORATOR_ENTRY.put("weblogic.net.http.Handler,openConnection", "com.k2cybersecurity.instrumentator.decorators.ssrf");

	}
}
