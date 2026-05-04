<?php
/**
 * Sentinel AI — PHP SDK
 * Drop this file into any PHP project and call Sentinel::check() at the top of every page.
 *
 * Usage:
 *   require_once 'sentinel.php';
 *   Sentinel::init('https://your-sentinel-api.com', 'sk-your-api-key-here');
 *   Sentinel::check(); // call this at the top of every page
 */

class Sentinel {

    private static string $api_url = '';
    private static string $api_key = '';

    /**
     * Set your Sentinel API URL and key.
     * Call this once before anything else.
     */
    public static function init(string $api_url, string $api_key): void {
        self::$api_url = rtrim($api_url, '/');
        self::$api_key = $api_key;
    }

    /**
     * Check the current request against Sentinel.
     * Call this at the very top of every PHP page you want to protect.
     * If the request is malicious, execution stops immediately and a 403 is returned.
     */
    public static function check(): void {
        $ip      = self::get_ip();
        $payload = self::get_payload();

        $result = self::call_api('/check', [
            'ip'      => $ip,
            'payload' => $payload,
        ]);

        if (!$result) {
            // If Sentinel is unreachable, fail open (allow) so your site stays up
            return;
        }

        if (isset($result['decision']) && $result['decision'] === 'block') {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode([
                'error'  => 'Request blocked by Sentinel AI',
                'reason' => $result['reason'] ?? 'Security policy violation',
            ]);
            exit;
        }
    }

    /**
     * Manually check any string payload.
     * Returns the full result array from the API.
     */
    public static function inspect(string $ip, string $payload): ?array {
        return self::call_api('/check', [
            'ip'      => $ip,
            'payload' => $payload,
        ]);
    }

    /**
     * Get all blocked IPs for your site.
     */
    public static function get_blacklist(): ?array {
        return self::call_api('/blacklist', [], 'GET');
    }

    /**
     * Unblock an IP address.
     */
    public static function unblock(string $ip): ?array {
        return self::call_api('/blacklist', ['ip' => $ip], 'DELETE');
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static function get_ip(): string {
        $headers = [
            'HTTP_CF_CONNECTING_IP',   // Cloudflare
            'HTTP_X_FORWARDED_FOR',    // Proxies / load balancers
            'HTTP_X_REAL_IP',          // Nginx proxy
            'REMOTE_ADDR',             // Direct connection
        ];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = trim(explode(',', $_SERVER[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }

    private static function get_payload(): array {
        $payload = [];

        // GET params
        if (!empty($_GET)) {
            $payload['get'] = $_GET;
        }

        // POST params
        if (!empty($_POST)) {
            $payload['post'] = $_POST;
        }

        // Raw JSON body
        $raw = file_get_contents('php://input');
        if ($raw) {
            $decoded = json_decode($raw, true);
            if ($decoded) {
                $payload['body'] = $decoded;
            } else {
                $payload['body'] = $raw;
            }
        }

        // Headers worth checking
        $payload['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

        return $payload;
    }

    private static function call_api(string $endpoint, array $data = [], string $method = 'POST'): ?array {
        if (empty(self::$api_url) || empty(self::$api_key)) {
            error_log('[Sentinel] Not initialized. Call Sentinel::init() first.');
            return null;
        }

        $url = self::$api_url . $endpoint;

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3); // 3 second timeout — won't slow your site
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'x-api-key: ' . self::$api_key,
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        } elseif ($method === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($ch);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($error) {
            error_log('[Sentinel] API error: ' . $error);
            return null;
        }

        return json_decode($response, true);
    }
}