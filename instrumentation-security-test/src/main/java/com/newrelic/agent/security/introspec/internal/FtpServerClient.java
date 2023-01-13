package com.newrelic.agent.security.introspec.internal;

import org.apache.commons.net.PrintCommandListener;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.junit.rules.ExternalResource;
import org.mockftpserver.fake.FakeFtpServer;
import org.mockftpserver.fake.UserAccount;
import org.mockftpserver.fake.filesystem.DirectoryEntry;
import org.mockftpserver.fake.filesystem.FileEntry;
import org.mockftpserver.fake.filesystem.FileSystem;
import org.mockftpserver.fake.filesystem.UnixFakeFileSystem;

import java.io.IOException;
import java.io.PrintWriter;

public class FtpServerClient extends ExternalResource {

    private String server;
    private int port;
    private String user;
    private String password;
    private String dir;
    private FTPClient ftp;

    private FakeFtpServer fakeServer;

    // constructor

    public FtpServerClient(String server, int port, String user, String password, String dir) {
        this.server = server;
        this.port = port;
        this.user = user;
        this.password = password;
        this.dir = dir;
        this.fakeServer = startServer();
    }

    public FakeFtpServer getFakeServer() {
        return fakeServer;
    }

    public String getURL() {
        return String.format("ftp://%s:%s@localhost:%d", user, password, port);
    }

    private FakeFtpServer startServer() {
        FakeFtpServer fakeFtpServer = new FakeFtpServer();
        fakeFtpServer.addUserAccount(new UserAccount(user, password, dir));

        FileSystem fileSystem = new UnixFakeFileSystem();
        fileSystem.add(new DirectoryEntry(dir));
        fileSystem.add(new FileEntry(dir+"/foobar.txt", "abcdef 1234567890"));
        fakeFtpServer.setFileSystem(fileSystem);
        fakeFtpServer.setServerControlPort(port);
        fakeFtpServer.start();
        if (fakeFtpServer.isStarted()) {
            port = fakeFtpServer.getServerControlPort();
        }
        return fakeFtpServer;
    }

    public void open() throws IOException {
        ftp = new FTPClient();

        ftp.addProtocolCommandListener(new PrintCommandListener(new PrintWriter(System.out)));

        ftp.connect(server, port);
        int reply = ftp.getReplyCode();
        if (!FTPReply.isPositiveCompletion(reply)) {
            ftp.disconnect();
            throw new IOException("Exception in connecting to FTP Server");
        }

        ftp.login(user, password);
    }

    public void close() throws IOException {
        ftp.disconnect();
    }
}