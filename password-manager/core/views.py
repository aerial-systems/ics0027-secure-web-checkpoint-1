from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_safe


@require_safe
def index(request):
    return render(request, "core/index.html", {"title": "Secure Password Manager"})


@require_safe
def health(request):
    return JsonResponse(
        {"status": "ok", "application": "vault", "stage": "checkpoint-1"}
    )
