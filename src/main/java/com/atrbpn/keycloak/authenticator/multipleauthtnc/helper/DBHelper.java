package com.atrbpn.keycloak.authenticator.multipleauthtnc.helper;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.sql.*;

public class DBHelper {

    private static HikariConfig config = new HikariConfig();
    private static HikariDataSource ds;

    private static final Logger log = LoggerFactory.getLogger(DBHelper.class);

    static {

        try {
            Context initCxt =  new InitialContext();

            String oracleUser = (String) initCxt.lookup("java:/oracleUser");
            String oraclePassword = (String) initCxt.lookup("java:/oraclePassword");
            String oracleUrl = (String) initCxt.lookup("java:/oracleUrl");

            config.setJdbcUrl(oracleUrl);
            config.setUsername(oracleUser);
            config.setPassword(oraclePassword);

        } catch (Exception ex) {
            log.error("unable to get database connection for Oracle");
            log.error(ex.getMessage(), ex);
        }

        config.setDriverClassName("oracle.jdbc.OracleDriver");
        config.setConnectionTestQuery("SELECT 1 FROM dual");
        config.setMinimumIdle(1);
        config.setMaximumPoolSize(10);
        config.setPoolName("RH-SSO Hikari Pooling");

        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        ds = new HikariDataSource(config);
    }

    public static Connection getConnection( ) throws SQLException {
        return ds.getConnection();
    }

    public static void closeQuietly(Connection connection) {
        try {
            if(connection != null)
                connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void closeQuietly(ResultSet resultSet) {
        try {
            if(resultSet != null)
                resultSet.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void closeQuietly(PreparedStatement preparedStatement) {
        try {
            if(preparedStatement != null)
                preparedStatement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
