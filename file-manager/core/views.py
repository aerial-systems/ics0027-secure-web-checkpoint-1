from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_safe


@require_safe
def index(request):
    return render(
        request, "core/index.html", {"title": "Secure File Encryption and Management"}
    )


@require_safe
def health(request):
    return JsonResponse(
        {"status": "ok", "application": "files", "stage": "checkpoint-1"}
    )
