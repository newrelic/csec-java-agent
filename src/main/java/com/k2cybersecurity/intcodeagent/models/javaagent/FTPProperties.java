package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class FTPProperties {

    private boolean enableFtp;

    private Integer port;

    private String username;

    private String password;

    public FTPProperties() {
    }

    /**
     * @return the enableFtp
     */
    public boolean isEnableFtp() {
        return enableFtp;
    }

    /**
     * @param enableFtp the enableFtp to set
     */
    public void setEnableFtp(boolean enableFtp) {
        this.enableFtp = enableFtp;
    }

    /**
     * @return the port
     */
    public Integer getPort() {
        return port;
    }

    /**
     * @param port the port to set
     */
    public void setPort(Integer port) {
        this.port = port;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @param username the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
