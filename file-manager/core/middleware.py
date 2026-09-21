class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.get_host()
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'none'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; base-uri 'none'; "
            "object-src 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response["Cache-Control"] = "no-store"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response
