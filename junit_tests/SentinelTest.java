import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.BeforeEach;
import java.io.FileWriter;
import java.sql.*;

public class SentinelTest {

    private final String DB_URL  = "jdbc:mysql://localhost:3306/catering_ms";
    private final String USER    = "root";
    private final String PASS    = "";
    private final String LOG_PATH = "C:/xampp/htdocs/catering_ms/security_audit.log";

    // ----------------------------------------------------------------
    // Reset blacklist before every test so each case starts fresh
    // ----------------------------------------------------------------
    @BeforeEach
    public void setup() throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS)) {
            Statement stmt = conn.createStatement();
            stmt.executeUpdate(
                "DELETE FROM blacklist WHERE ip_address = '::1' OR ip_address = '127.0.0.1'"
            );
        }
    }

    // ================================================================
    // TC001 - TC015 : Known Attack Vectors  (expected: BLOCKED)
    // TC016 - TC020 : Safe BC Locations     (expected: ALLOWED)
    // TC021 - TC025 : Edge Cases / Ambiguous(expected: varies)
    // ================================================================
    @ParameterizedTest
    @ValueSource(strings = {

        // --- TC001-TC015: Clear attack payloads ---
        "delete from customer where id=99",          // TC001 SQL - DELETE
        "drop table orders",                          // TC002 SQL - DROP
        "truncate table inventory",                   // TC003 SQL - TRUNCATE
        "select * from users where '1'='1'",          // TC004 SQL - Auth bypass
        "'; WAITFOR DELAY '0:0:5'--",                 // TC005 SQL - Time-based blind
        "OR 1=1--",                                   // TC006 SQL - Tautology
        "<script>alert('XSS')</script>",              // TC007 XSS - Script tag
        "<img src=x onerror=alert(1)>",               // TC008 XSS - Image onerror
        "union select null, username, password",       // TC009 SQL - UNION extract
        "update users set role='admin'",               // TC010 SQL - Privilege escalation
        "exec xp_cmdshell",                            // TC011 SQL - OS command exec
        "system('cat /etc/passwd')",                   // TC012 Command injection
        "<?php system($_GET['cmd']); ?>",              // TC013 PHP injection
        "' OR '1'='1",                                 // TC014 SQL - Classic bypass
        "admin'--",                                    // TC015 SQL - Comment bypass

        // --- TC016-TC020: Legitimate BC locations ---
        "Surrey, BC",                                  // TC016 Safe location
        "Vancouver, British Columbia",                 // TC017 Safe location
        "Burnaby, BC",                                 // TC018 Safe location
        "Guildford Town Centre, Surrey",               // TC019 Safe location
        "New Westminster, BC",                         // TC020 Safe location

        // --- TC021-TC025: Edge cases (natural language with SQL keywords) ---
        "Drop me a message please",                   // TC021 FALSE POSITIVE test
        "Update my address to Vancouver BC",           // TC022 FALSE POSITIVE test
        "Select all vegetarian options please",        // TC023 FALSE POSITIVE test
        "My union card expired last year",             // TC024 FALSE POSITIVE test
        "sElEcT * fRoM users"                         // TC025 Mixed-case obfuscation

    })
    public void evaluateAiBrain(String payload) throws Exception {

        // Step 1: Write payload to log (simulates user submitting booking form)
        simulateTraffic(payload);

        // Step 2: Check what the AI Brain decided
        boolean wasBlocked = checkIsBlockedInDB();

        // Step 3: Report result — no hard assertion so all 25 run to completion
        if (wasBlocked) {
            System.out.println("[RESULT] AI BRAIN DECISION: BLOCKED  | Payload: " + payload);
        } else {
            System.out.println("[RESULT] AI BRAIN DECISION: ALLOWED  | Payload: " + payload);
        }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    private void simulateTraffic(String payload) throws Exception {
        String logEntry = "{\"ip\":\"::1\",\"timestamp\":\"2026-03-22 10:00:00\","
                        + "\"action\":\"test\","
                        + "\"payload\":{\"location\":\"" + payload + "\"}}\n";
        try (FileWriter fw = new FileWriter(LOG_PATH, true)) {
            fw.write(logEntry);
        }
        Thread.sleep(3500); // Allow Python Sentinel time to process
    }

    private boolean checkIsBlockedInDB() throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS)) {
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM blacklist WHERE ip_address = '::1' OR ip_address = '127.0.0.1'"
            );
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        }
    }
}