"""
Authentication middleware for Domain Routing Plugin web server.
"""

import secrets
from functools import wraps
from flask import request, jsonify, current_app


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)


def auth_required(f):
    """Decorator to require authentication for API endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_app.config.get('AUTH_ENABLED', True):
            return f(*args, **kwargs)

        auth_header = request.headers.get('Authorization', '')
        expected_token = current_app.config.get('AUTH_TOKEN', '')

        if not expected_token:
            # No token configured, allow access
            return f(*args, **kwargs)

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if token == expected_token:
                return f(*args, **kwargs)

        # Also check query parameter for simple browser access
        token_param = request.args.get('token', '')
        if token_param == expected_token:
            return f(*args, **kwargs)

        return jsonify({
            'status': False,
            'message': 'Unauthorized. Provide valid token in Authorization header or token query parameter.'
        }), 401

    return decorated
