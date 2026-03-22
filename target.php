<?php
session_start();

// Database connection - update these to match your setup
$host = 'localhost';
$user = 'root';
$pass = '';
$db   = 'sentinel_test';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed. Make sure you ran setup.sql first.");
}

// ---------------------------------------------------------------
// SENTINEL AI — Access Control Layer
// This checks the blacklist on every page load.
// If the IP is blacklisted by the Python sentinel, show denied.
// ---------------------------------------------------------------
$ip = $_SERVER['REMOTE_ADDR'];
$check = $pdo->prepare("SELECT attack_type FROM blacklist WHERE ip_address = ?");
$check->execute([$ip]);
$blocked = $check->fetch();

if ($blocked) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Access Denied — Sentinel AI</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                background: #c0392b;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                text-align: center;
            }
            .box { max-width: 600px; padding: 40px; }
            h1 { font-size: 48px; margin-bottom: 20px; }
            .shield { font-size: 80px; margin-bottom: 20px; }
            .reason {
                background: rgba(0,0,0,0.2);
                padding: 15px 25px;
                border-radius: 8px;
                margin: 20px 0;
                font-family: monospace;
                font-size: 14px;
            }
            p { font-size: 16px; opacity: 0.9; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="box">
            <div class="shield">🛡️</div>
            <h1>ACCESS DENIED</h1>
            <div class="reason">
                Sentinel AI detected: <?php echo htmlspecialchars($blocked['attack_type']); ?>
            </div>
            <p>Your IP address has been automatically blacklisted.</p>
            <p>This incident has been logged for security review.</p>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// ---------------------------------------------------------------
// SENTINEL AI — Security Sensor (Logging Hook)
// This logs every form submission to security_audit.log
// so the Python sentinel can analyze it in real time.
// ---------------------------------------------------------------
$log_file = __DIR__ . '/security_audit.log';
$log_entry = json_encode([
    'ip'        => $_SERVER['REMOTE_ADDR'],
    'timestamp' => date('Y-m-d H:i:s'),
    'action'    => $_SERVER['REQUEST_METHOD'],
    'payload'   => $_POST
]) . PHP_EOL;
file_put_contents($log_file, $log_entry, FILE_APPEND);

// ---------------------------------------------------------------
// Handle form submission
// ---------------------------------------------------------------
$message = '';
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['location'])) {
    $location = $_POST['location'];
    $guests   = $_POST['guests'] ?? '';
    $date     = $_POST['date'] ?? '';

    // Save to bookings table
    $stmt = $pdo->prepare(
        "INSERT INTO bookings (location, guests, event_date, ip_address)
         VALUES (?, ?, ?, ?)"
    );
    $stmt->execute([$location, $guests, $date, $ip]);

    $submitted = true;
    $message = "Booking submitted successfully! Location: " . htmlspecialchars($location);
}

// Get recent bookings
$recent = $pdo->query("SELECT * FROM bookings ORDER BY id DESC LIMIT 5")->fetchAll();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Sentinel AI — Test Target Application</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
        }
        header {
            background: #1a252f;
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        header h1 { font-size: 22px; }
        header span {
            background: #27ae60;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
        }
        .container {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .notice {
            background: #fff3cd;
            border-left: 4px solid #f39c12;
            padding: 15px 20px;
            border-radius: 4px;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .notice strong { color: #e67e22; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .card h2 {
            font-size: 18px;
            margin-bottom: 20px;
            color: #1a252f;
            border-bottom: 2px solid #f0f2f5;
            padding-bottom: 10px;
        }
        label {
            display: block;
            font-size: 13px;
            font-weight: bold;
            color: #555;
            margin-bottom: 6px;
            margin-top: 16px;
        }
        input, select {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            font-family: Arial, sans-serif;
        }
        input:focus { outline: none; border-color: #2980b9; }
        .hint {
            font-size: 12px;
            color: #999;
            margin-top: 4px;
        }
        .attack-hints {
            background: #fdf2f8;
            border: 1px dashed #e91e8c44;
            border-radius: 6px;
            padding: 12px 16px;
            margin-top: 16px;
            font-size: 13px;
        }
        .attack-hints strong { color: #c0392b; }
        .attack-hints code {
            background: #f8f8f8;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            color: #c0392b;
        }
        button {
            margin-top: 20px;
            background: #2980b9;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 6px;
            font-size: 15px;
            cursor: pointer;
            width: 100%;
        }
        button:hover { background: #2471a3; }
        .success {
            background: #d4edda;
            border-left: 4px solid #27ae60;
            padding: 12px 18px;
            border-radius: 4px;
            margin-top: 16px;
            color: #155724;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th {
            background: #1a252f;
            color: white;
            padding: 10px 14px;
            text-align: left;
            font-weight: normal;
        }
        td {
            padding: 10px 14px;
            border-bottom: 1px solid #f0f2f5;
        }
        tr:hover td { background: #f9f9f9; }
        .sentinel-info {
            background: #eaf4fb;
            border-left: 4px solid #2980b9;
            padding: 15px 20px;
            border-radius: 4px;
            font-size: 13px;
            line-height: 1.7;
        }
    </style>
</head>
<body>

<header>
    <h1>🍽️ Catering Booking System — Sentinel AI Test Target</h1>
    <span>🛡️ Sentinel AI Active</span>
</header>

<div class="container">

    <div class="notice">
        <strong>⚠️ Testing Environment:</strong> This application is intentionally vulnerable to SQL injection
        in the location field. It is designed to demonstrate Sentinel AI's detection capabilities.
        Make sure <code>sentinel_brain.py</code> is running in a separate terminal before testing.
    </div>

    <div class="card">
        <h2>📋 Submit a Booking</h2>

        <?php if ($submitted): ?>
            <div class="success">✅ <?php echo $message; ?></div>
        <?php endif; ?>

        <form method="POST">
            <label>Event Location</label>
            <input type="text" name="location"
                   placeholder="e.g. Surrey, BC or Guildford Town Centre"
                   value="<?php echo isset($_POST['location']) ? htmlspecialchars($_POST['location']) : ''; ?>">
            <div class="hint">Try a normal location first, then try an attack payload below.</div>

            <div class="attack-hints">
                <strong>🔴 Test Attack Payloads</strong> — paste these into the location field:<br><br>
                SQL Injection: <code>' OR '1'='1</code><br>
                SQL Delete: <code>delete from bookings where id=1</code><br>
                XSS Attack: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                Command Injection: <code>system('cat /etc/passwd')</code><br>
                Obfuscated SQL: <code>sElEcT * fRoM bookings</code>
            </div>

            <label>Number of Guests</label>
            <input type="number" name="guests" placeholder="e.g. 50" min="1" max="500">

            <label>Event Date</label>
            <input type="date" name="date">

            <button type="submit">Submit Booking</button>
        </form>
    </div>

    <div class="card">
        <h2>📊 Recent Bookings</h2>
        <?php if (empty($recent)): ?>
            <p style="color:#999; font-size:14px;">No bookings yet. Submit one above.</p>
        <?php else: ?>
        <table>
            <tr>
                <th>#</th>
                <th>Location</th>
                <th>Guests</th>
                <th>Date</th>
                <th>IP</th>
                <th>Submitted</th>
            </tr>
            <?php foreach ($recent as $row): ?>
            <tr>
                <td><?php echo $row['id']; ?></td>
                <td><?php echo htmlspecialchars($row['location']); ?></td>
                <td><?php echo htmlspecialchars($row['guests']); ?></td>
                <td><?php echo htmlspecialchars($row['event_date']); ?></td>
                <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
                <td><?php echo $row['created_at']; ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
        <?php endif; ?>
    </div>

    <div class="card">
        <h2>🛡️ How Sentinel AI Works Here</h2>
        <div class="sentinel-info">
            1. You submit this form with any location text.<br>
            2. PHP logs the payload to <strong>security_audit.log</strong> instantly.<br>
            3. The Python sentinel reads the log every second.<br>
            4. If the payload looks malicious, your IP is added to the <strong>blacklist</strong> table in MySQL.<br>
            5. Next time you load any page, PHP checks the blacklist and shows the <strong>Access Denied</strong> screen.<br><br>
            <strong>To reset after a block:</strong> Run this in phpMyAdmin →
            <code>DELETE FROM blacklist WHERE ip_address = '::1';</code>
        </div>
    </div>

</div>
</body>
</html>
