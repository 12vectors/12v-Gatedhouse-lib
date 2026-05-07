package com.twelvevectors.gatedhouse;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;

@FunctionalInterface
public interface Database {

    Connection getConnection() throws SQLException;

    static Database fromUrl(String jdbcUrl, String user, String password) {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        return () -> DriverManager.getConnection(jdbcUrl, user, password);
    }
}
