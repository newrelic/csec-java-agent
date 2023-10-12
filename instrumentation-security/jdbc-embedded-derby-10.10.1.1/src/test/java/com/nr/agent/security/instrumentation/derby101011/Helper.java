package com.nr.agent.security.instrumentation.derby101011;

import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Helper {
    /**
     * This is used to deregister all the drivers loaded by the calling class loader
     * Introduced due to {@link org.apache.derby.jdbc.EmbeddedDriver} was not being
     * used even after registering with DriverManager
     */
    public static void setup(String url){
        while (true) {
            try {
                Driver driver = DriverManager.getDriver(url);
//                System.out.println("...UNLOAD "+driver.getClass()+"...");
                DriverManager.deregisterDriver(driver);
            } catch (SQLException e) {
                break;
            }
        }
    }
}
