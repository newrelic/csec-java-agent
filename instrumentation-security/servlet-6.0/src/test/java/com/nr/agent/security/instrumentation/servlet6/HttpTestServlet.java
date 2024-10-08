package com.nr.agent.security.instrumentation.servlet6;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
public class HttpTestServlet extends HttpServlet {
    public HttpTestServlet () {
        super();
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String path = request.getRequestURI();

        if(path.equals("/request")){

            testServletRequestHooks( request, response);

        }else if(path.equals("/response")){

            testServletResponseHooks( request, response);

        } else if(path.equals("/inputStream/read")){

            ServletInputStream in = request.getInputStream();
            while(!in.isFinished()){
                in.read();
            }

        } else if(path.equals("/inputStream/read/byte-param")){

            ServletInputStream in = request.getInputStream();
            while(!in.isFinished()){
                byte[] b = new byte[in.available()];
                in.read(b);
            }

        } else if(path.equals("/inputStream/read/3-params")){

            ServletInputStream in = request.getInputStream();
            while(!in.isFinished()){
                byte[] b = new byte[in.available()];
                in.read(b, 0, b.length);
            }

        } else if(path.equals("/inputStream/readLine")){

            ServletInputStream in = request.getInputStream();
            while(!in.isFinished()){
                byte[] b = new byte[in.available()];
                in.readLine(b, 0, b.length);
            }

        } else if(path.equals("/inputStream/readLine/withOff")){

            ServletInputStream in = request.getInputStream();
            byte[] b = new byte[10];
            in.readLine(b, 5, 5);
            in.close();

        } else if(path.equals("/outputStream/write")) {

            String type = request.getParameter("type");
            testWriteHooks( response, type);

        } else if(path.equals("/outputStream/print")){

            String type = request.getParameter("type");
            print(response, type);

        } else if(path.equals("/outputStream/println")){

            String type = request.getParameter("type");
            println(response, type);

        }

    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getRequestURI();

         if(path.equals("/session")){
            HttpSession session = request.getSession(true);
            session.setAttribute("key", "value");
        } else if(path.equals("/session/securecookie")){
             Cookie cookie = new Cookie("key", "value");
             cookie.setSecure(true);
             response.addCookie(cookie);
        }  else if(path.equals("/session/cookie")){
             // add insecure cookie to response
             response.addCookie(new Cookie("key", "value"));
         } else if (path.equals("/session/secure_cookies")) {
             // add multiple secure cookies to response
             Cookie cookie = new Cookie("secure-cookie-1", "value");
             cookie.setSecure(true);
             response.addCookie(cookie);

             Cookie cookie1 = new Cookie("secure-cookie-2", "value");
             cookie1.setSecure(true);
             cookie1.setHttpOnly(true);
             response.addCookie(cookie1);
         } else if (path.equals("/session/insecure_cookies")) {
             // add multiple insecure cookies to response
             response.addCookie(new Cookie("insecure-cookie-1", "value"));
             response.addCookie(new Cookie("insecure-cookie-2", "value"));
         } else if (path.equals("/session/cookies")){
             // add multiple cookies to response
             Cookie cookie = new Cookie("secure-cookie", "value");
             cookie.setSecure(true);
             response.addCookie(cookie);

             response.addCookie(new Cookie("insecure-cookie","value"));
         } else if (path.equals("/session/single-cookie")){
             Cookie cookie = new Cookie("cookie", "value");
             cookie.setSecure(true);
             cookie.setHttpOnly(true);
             response.addCookie(cookie);
         }
    }

    private void testServletRequestHooks( HttpServletRequest request, HttpServletResponse response) throws IOException {
        String reqHook = request.getParameter("hook");

        if(reqHook.equals("getInputStream")){

            ServletInputStream in = request.getInputStream();
            writeHashcode(response, in.hashCode());

        } else if (reqHook.equals("getReader")) {

            BufferedReader in = request.getReader();
            in.read();
            writeHashcode(response, in.hashCode());

        } else if (reqHook.equals("getParameterValues")){

            request.getParameterValues("val");

        } else if (reqHook.equals("getParameterMap")) {

            request.getParameterMap();

        }
    }

    private void testServletResponseHooks( HttpServletRequest request, HttpServletResponse response) throws IOException {
        String reqHook = request.getParameter("hook");

        if(reqHook.equals("getOutputStream")){

            writeHashcode(response, response.getOutputStream().hashCode());

        } else if (reqHook.equals("getWriter")) {

            PrintWriter out = response.getWriter();
            out.print(out.hashCode());
            out.flush();

        }
    }

    private void testWriteHooks ( HttpServletResponse response, String type) throws IOException {
        response.setContentType("multipart/form-data");

        if( type.equals("no-param")) {

            ServletOutputStream out = response.getOutputStream();
            out.write('2');
            out.flush();

        } else if( type.equals("byte-param")) {

            ServletOutputStream out = response.getOutputStream();

            out.write(type.getBytes());
            out.flush();

        } else if( type.equals("3-param")) {

            ServletOutputStream out = response.getOutputStream();
            out.write(type.getBytes(), 0, type.length());
            out.flush();

        }

    }
    private void writeHashcode(HttpServletResponse response, int hashcode) throws IOException {

        ServletOutputStream out = response.getOutputStream();
        out.print(hashcode);
        out.flush();

    }

    private void print(HttpServletResponse response, String type) throws IOException {

        if(type.equals("String")){

            ServletOutputStream out = response.getOutputStream();
            out.print("test");
            out.flush();

        } else if (type.equals("boolean")) {

            ServletOutputStream out = response.getOutputStream();
            out.print(true);
            out.flush();

        }else if (type.equals("char")) {

            ServletOutputStream out = response.getOutputStream();
            out.print('c');
            out.flush();

        }else if (type.equals("int")) {

            ServletOutputStream out = response.getOutputStream();
            out.print(1);
            out.flush();

        }else if (type.equals("long")) {

            ServletOutputStream out = response.getOutputStream();
            out.print(1L);
            out.flush();

        }else if (type.equals("float")) {

            ServletOutputStream out = response.getOutputStream();
            out.print(1.1f);
            out.flush();

        }else if (type.equals("double")) {

            ServletOutputStream out = response.getOutputStream();
            out.print(1.1d);
            out.flush();

        }

    }

    private void println(HttpServletResponse response, String type) throws IOException {
        if(type.equals("null")){
            ServletOutputStream out = response.getOutputStream();
            out.println();
            out.flush();
        }
        else if(type.equals("String")){
            ServletOutputStream out = response.getOutputStream();
            out.println("test");
            out.flush();
        } else if (type.equals("boolean")) {
            ServletOutputStream out = response.getOutputStream();
            out.println(true);
            out.flush();
        }else if (type.equals("char")) {
            ServletOutputStream out = response.getOutputStream();
            out.println('c');
            out.flush();
        }else if (type.equals("int")) {
            ServletOutputStream out = response.getOutputStream();
            out.println(1);
            out.flush();
        }else if (type.equals("long")) {
            ServletOutputStream out = response.getOutputStream();
            out.println(1L);
            out.flush();
        }else if (type.equals("float")) {
            ServletOutputStream out = response.getOutputStream();
            out.println(1.1f);
            out.flush();
        }else if (type.equals("double")) {
            ServletOutputStream out = response.getOutputStream();
            out.println(1.1d);
            out.flush();
        }
    }
}