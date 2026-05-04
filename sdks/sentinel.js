/**
 * Sentinel AI — JavaScript SDK
 * Works with Node.js, Express, Next.js, or any JS backend.
 *
 * Usage (Express):
 *   const sentinel = require('./sentinel');
 *   sentinel.init('https://your-sentinel-api.com', 'sk-your-key');
 *   app.use(sentinel.middleware());
 *
 * Usage (manual check):
 *   const result = await sentinel.check(req.ip, req.body);
 *   if (result.decision === 'block') return res.status(403).json({ error: 'Blocked' });
 */

const https = require('https');
const http  = require('http');

let _apiUrl = '';
let _apiKey = '';

/**
 * Set your Sentinel API URL and key.
 * Call this once when your app starts.
 */
function init(apiUrl, apiKey) {
    _apiUrl = apiUrl.replace(/\/$/, '');
    _apiKey = apiKey;
}

/**
 * Check a single request payload against Sentinel.
 * Returns the full result object: { decision, reason, confidence, ip }
 */
async function check(ip, payload) {
    try {
        const result = await callApi('/check', {
            ip:      ip,
            payload: payload,
        });
        return result;
    } catch (err) {
        console.error('[Sentinel] Check failed:', err.message);
        // Fail open — if Sentinel is unreachable, don't block your users
        return { decision: 'allow', reason: 'Sentinel unreachable', confidence: 0 };
    }
}

/**
 * Express middleware — drop this in and every route is protected automatically.
 *
 * app.use(sentinel.middleware());
 */
function middleware() {
    return async (req, res, next) => {
        const ip      = getIp(req);
        const payload = getPayload(req);

        const result = await check(ip, payload);

        if (result.decision === 'block') {
            return res.status(403).json({
                error:  'Request blocked by Sentinel AI',
                reason: result.reason,
            });
        }

        // Attach result to req so your routes can inspect it
        req.sentinel = result;
        next();
    };
}

/**
 * Get all blocked IPs for your site.
 */
async function getBlacklist() {
    return callApi('/blacklist', null, 'GET');
}

/**
 * Unblock an IP address.
 */
async function unblock(ip) {
    return callApi('/blacklist', { ip }, 'DELETE');
}

/**
 * Get recent events for your site.
 */
async function getEvents() {
    return callApi('/events', null, 'GET');
}

// ---------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------

function getIp(req) {
    return (
        req.headers['cf-connecting-ip']    ||  // Cloudflare
        req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.headers['x-real-ip']           ||
        req.socket?.remoteAddress          ||
        '0.0.0.0'
    );
}

function getPayload(req) {
    return {
        method:     req.method,
        path:       req.path || req.url,
        query:      req.query || {},
        body:       req.body  || {},
        user_agent: req.headers['user-agent'] || '',
    };
}

function callApi(endpoint, data, method = 'POST') {
    return new Promise((resolve, reject) => {
        if (!_apiUrl || !_apiKey) {
            return reject(new Error('[Sentinel] Not initialized. Call sentinel.init() first.'));
        }

        const url     = new URL(_apiUrl + endpoint);
        const body    = data ? JSON.stringify(data) : null;
        const isHttps = url.protocol === 'https:';
        const lib     = isHttps ? https : http;

        const options = {
            hostname: url.hostname,
            port:     url.port || (isHttps ? 443 : 80),
            path:     url.pathname,
            method:   method,
            headers: {
                'Content-Type': 'application/json',
                'x-api-key':    _apiKey,
            },
            timeout: 3000, // 3 seconds
        };

        if (body) {
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        const req = lib.request(options, (res) => {
            let raw = '';
            res.on('data', chunk => raw += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(raw));
                } catch {
                    reject(new Error('Invalid JSON from Sentinel API'));
                }
            });
        });

        req.on('error',   reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Sentinel API timeout'));
        });

        if (body) req.write(body);
        req.end();
    });
}

module.exports = { init, check, middleware, getBlacklist, unblock, getEvents };