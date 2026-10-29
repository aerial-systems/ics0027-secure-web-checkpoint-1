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


class RequestLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.http import HttpResponse

        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return HttpResponse("Invalid request size.", status=400)
        if length < 0 or length > 11 * 1024 * 1024:
            return HttpResponse("Request exceeds limit.", status=413)
        return self.get_response(request)


class SessionLifetimeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        import time

        from django.contrib.auth import logout

        if request.user.is_authenticated:
            now = time.time()
            started = request.session.get("login_at", 0)
            active = request.session.get("activity_at", 0)
            if now - started >= 28800 or now - active >= 900:
                logout(request)
            else:
                request.session["activity_at"] = now
        return self.get_response(request)
