"""
Sentinel AI — Python SDK
Works with Django, Flask, FastAPI, or any Python backend.

Usage (Flask):
    from sentinel import Sentinel
    sentinel = Sentinel('https://your-sentinel-api.com', 'sk-your-key')

    @app.before_request
    def protect():
        result = sentinel.check_request(request)
        if result['decision'] == 'block':
            return jsonify({'error': 'Blocked by Sentinel'}), 403

Usage (Django middleware):
    # In settings.py add 'sentinel_middleware.SentinelMiddleware' to MIDDLEWARE
    # Create sentinel_middleware.py using the DjangoMiddleware class below
"""

import httpx
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Sentinel:

    def __init__(self, api_url: str, api_key: str, timeout: float = 3.0):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.headers = {
            'Content-Type': 'application/json',
            'x-api-key':    api_key,
        }

    def check(self, ip: str, payload: dict | str) -> dict:
        """
        Check a payload against Sentinel.
        Returns dict with decision, reason, confidence, ip.
        """
        try:
            r = httpx.post(
                f"{self.api_url}/check",
                json={'ip': ip, 'payload': payload},
                headers=self.headers,
                timeout=self.timeout,
            )
            return r.json()
        except Exception as e:
            logger.warning(f"[Sentinel] Unreachable: {e}")
            # Fail open — don't block users if Sentinel is down
            return {'decision': 'allow', 'reason': 'Sentinel unreachable', 'confidence': 0}

    def check_flask_request(self, request) -> dict:
        """
        Pass a Flask request object directly.
        Automatically extracts IP and payload.
        """
        ip      = self._get_ip_flask(request)
        payload = self._get_payload_flask(request)
        return self.check(ip, payload)

    def get_blacklist(self) -> dict:
        r = httpx.get(
            f"{self.api_url}/blacklist",
            headers=self.headers,
            timeout=self.timeout,
        )
        return r.json()

    def unblock(self, ip: str) -> dict:
        r = httpx.delete(
            f"{self.api_url}/blacklist",
            json={'ip': ip},
            headers=self.headers,
            timeout=self.timeout,
        )
        return r.json()

    def get_events(self) -> dict:
        r = httpx.get(
            f"{self.api_url}/events",
            headers=self.headers,
            timeout=self.timeout,
        )
        return r.json()

    # ---------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------

    def _get_ip_flask(self, request) -> str:
        return (
            request.headers.get('CF-Connecting-IP') or
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request.headers.get('X-Real-IP') or
            request.remote_addr or
            '0.0.0.0'
        )

    def _get_payload_flask(self, request) -> dict:
        payload = {
            'method':     request.method,
            'path':       request.path,
            'query':      dict(request.args),
            'user_agent': request.headers.get('User-Agent', ''),
        }
        if request.form:
            payload['form'] = dict(request.form)
        if request.is_json:
            payload['body'] = request.get_json(silent=True) or {}
        return payload


class DjangoMiddleware:
    """
    Django middleware class.

    In settings.py:
        SENTINEL_API_URL = 'https://your-sentinel-api.com'
        SENTINEL_API_KEY = 'sk-your-key'

    In settings.py MIDDLEWARE list, add at the top:
        'path.to.sentinel_middleware.SentinelMiddleware'
    """

    def __init__(self, get_response):
        from django.conf import settings
        self.get_response = get_response
        self.sentinel = Sentinel(
            api_url=settings.SENTINEL_API_URL,
            api_key=settings.SENTINEL_API_KEY,
        )

    def __call__(self, request):
        ip      = self._get_ip(request)
        payload = self._get_payload(request)
        result  = self.sentinel.check(ip, payload)

        if result.get('decision') == 'block':
            from django.http import JsonResponse
            return JsonResponse({
                'error':  'Request blocked by Sentinel AI',
                'reason': result.get('reason'),
            }, status=403)

        request.sentinel = result
        return self.get_response(request)

    def _get_ip(self, request) -> str:
        return (
            request.META.get('HTTP_CF_CONNECTING_IP') or
            request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or
            request.META.get('REMOTE_ADDR') or
            '0.0.0.0'
        )

    def _get_payload(self, request) -> dict:
        return {
            'method':     request.method,
            'path':       request.path,
            'query':      dict(request.GET),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }