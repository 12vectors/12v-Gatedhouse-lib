package com.twelvevectors.gatedhouse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Migrator {

    private static final String MIGRATIONS_RESOURCE_DIR =
        "com/twelvevectors/gatedhouse/migrations";
    private static final String MIGRATIONS_INDEX = MIGRATIONS_RESOURCE_DIR + "/migrations.txt";
    private static final Pattern FILENAME =
        Pattern.compile("^V(\\d+)__([A-Za-z0-9_]+)\\.sql$");

    // Constant key for pg_advisory_lock; arbitrary but stable.
    private static final long ADVISORY_LOCK_KEY = 0x6761746564686F75L; // 'gatedhou'

    private Migrator() {
    }

    static void migrate(Database database) throws SQLException, IOException {
        List<Migration> available = loadAvailableMigrations();

        try (Connection conn = database.getConnection()) {
            conn.setAutoCommit(true);
            acquireLock(conn);
            try {
                ensureBookkeeping(conn);
                Set<Integer> applied = appliedVersions(conn);
                for (Migration m : available) {
                    if (applied.contains(m.version)) {
                        continue;
                    }
                    apply(conn, m);
                }
            } finally {
                releaseLock(conn);
            }
        }
    }

    // ---- migration discovery -------------------------------------------------

    private static List<Migration> loadAvailableMigrations() throws IOException {
        List<String> filenames = readIndex();
        List<Migration> out = new ArrayList<>(filenames.size());
        for (String filename : filenames) {
            Matcher m = FILENAME.matcher(filename);
            if (!m.matches()) {
                throw new IOException("Migration filename does not match expected V###__name.sql: " + filename);
            }
            int version = Integer.parseInt(m.group(1));
            String name = m.group(2);
            String sql = readResource(MIGRATIONS_RESOURCE_DIR + "/" + filename);
            String checksum = sha256Hex(sql);
            out.add(new Migration(version, name, sql, checksum));
        }
        out.sort((a, b) -> Integer.compare(a.version, b.version));
        return out;
    }

    private static List<String> readIndex() throws IOException {
        List<String> out = new ArrayList<>();
        try (InputStream in = openResource(MIGRATIONS_INDEX);
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                out.add(trimmed);
            }
        }
        return out;
    }

    private static String readResource(String path) throws IOException {
        try (InputStream in = openResource(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static InputStream openResource(String path) throws IOException {
        InputStream in = Migrator.class.getClassLoader().getResourceAsStream(path);
        if (in == null) {
            throw new IOException("Migration resource not found on classpath: " + path);
        }
        return in;
    }

    // ---- bookkeeping ---------------------------------------------------------

    private static void acquireLock(Connection conn) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT pg_advisory_lock(?)")) {
            ps.setLong(1, ADVISORY_LOCK_KEY);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
            }
        }
    }

    private static void releaseLock(Connection conn) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT pg_advisory_unlock(?)")) {
            ps.setLong(1, ADVISORY_LOCK_KEY);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
            }
        }
    }

    private static void ensureBookkeeping(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS gatedhouse");
            st.execute(
                "CREATE TABLE IF NOT EXISTS gatedhouse.schema_versions ("
                + "    version    INTEGER PRIMARY KEY,"
                + "    name       TEXT NOT NULL,"
                + "    checksum   TEXT NOT NULL,"
                + "    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
                + ")");
        }
    }

    private static Set<Integer> appliedVersions(Connection conn) throws SQLException {
        Set<Integer> out = new HashSet<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT version FROM gatedhouse.schema_versions")) {
            while (rs.next()) {
                out.add(rs.getInt(1));
            }
        }
        return out;
    }

    // ---- application ---------------------------------------------------------

    private static void apply(Connection conn, Migration m) throws SQLException {
        boolean prevAutoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            try (Statement st = conn.createStatement()) {
                st.execute(m.sql);
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO gatedhouse.schema_versions (version, name, checksum) VALUES (?, ?, ?)")) {
                ps.setInt(1, m.version);
                ps.setString(2, m.name);
                ps.setString(3, m.checksum);
                ps.executeUpdate();
            }
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            throw new SQLException("Migration V" + m.version + " (" + m.name + ") failed", e);
        } finally {
            conn.setAutoCommit(prevAutoCommit);
        }
    }

    // ---- helpers -------------------------------------------------------------

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private record Migration(int version, String name, String sql, String checksum) {
    }
}
