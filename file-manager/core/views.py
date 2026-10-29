import time

from cryptography.exceptions import InvalidTag
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, transaction
from django.db.models import F
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.crypto import salted_hmac
from django.utils.http import content_disposition_header
from django.views.decorators.http import (
    require_http_methods,
    require_POST,
    require_safe,
)

from . import crypto
from .auth import allowed
from .forms import NameForm, RegisterForm, UploadForm
from .models import AuditEvent, StoredFile, Usage


def audit(request, action, outcome, object_id=""):
    session_key = request.session.session_key
    tag = (
        salted_hmac("file-manager.audit", session_key, algorithm="sha256").hexdigest()
        if session_key
        else ""
    )
    AuditEvent.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        action=action,
        outcome=outcome,
        object_id=str(object_id),
        source=request.META.get("REMOTE_ADDR") or None,
        session_tag=tag,
    )


def owned_file(request, file_id, action):
    try:
        return get_object_or_404(StoredFile, pk=file_id, owner=request.user)
    except Http404:
        audit(request, action, "denied", file_id)
        raise


@require_safe
def index(request):
    return render(request, "core/index.html", {"title": "Secure File Manager"})


@require_safe
def health(request):
    return JsonResponse(
        {"status": "ok", "application": "files", "stage": "checkpoint-2-draft"}
    )


@require_http_methods(["GET", "POST"])
def register(request):
    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            user = form.save()
            Usage.objects.create(owner=user)
        return redirect("login")
    return render(request, "core/form.html", {"form": form, "title": "Create account"})


@require_http_methods(["GET", "POST"])
def sign_in(request):
    error = ""
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        if (
            len(username) <= 150
            and len(password) <= 128
            and allowed(username, request.META.get("REMOTE_ADDR", ""))
        ):
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                now = time.time()
                request.session["login_at"] = request.session["activity_at"] = now
                audit(request, "login", "success")
                return redirect("files")
        error = "Sign-in failed. Check your details or try again later."
        audit(request, "login", "denied")
    return render(request, "core/login.html", {"error": error})


@login_required
@require_POST
def sign_out(request):
    audit(request, "logout", "success")
    logout(request)
    return redirect("index")


@login_required
@require_safe
def files(request):
    return render(
        request,
        "core/files.html",
        {
            "files": StoredFile.objects.filter(owner=request.user).defer(
                "ciphertext", "wrapped_key"
            ),
            "form": UploadForm(),
            "username": request.user.username,
        },
    )


@login_required
@require_POST
def upload(request):
    form = UploadForm(request.POST, request.FILES)
    if (
        getattr(request, "upload_too_large", False)
        or len(request.FILES.getlist("file")) != 1
    ):
        return HttpResponse("Upload exactly one file of at most 10 MiB.", status=400)
    if not form.is_valid():
        return render(
            request,
            "core/form.html",
            {"form": form, "title": "Upload", "multipart": True},
            status=400,
        )
    item = form.cleaned_data["file"]
    data = item.read(settings.MAX_FILE_BYTES + 1)
    if len(data) > settings.MAX_FILE_BYTES:
        return HttpResponse("File exceeds limit.", status=400)
    record = StoredFile(owner=request.user, name=item.name, size=len(data))
    try:
        crypto.encrypt(record, data)
        with transaction.atomic():
            Usage.objects.get_or_create(owner=request.user)
            if not Usage.objects.filter(
                owner=request.user, used__lte=settings.USER_QUOTA_BYTES - len(data)
            ).update(used=F("used") + len(data)):
                return HttpResponse("Storage quota exceeded.", status=400)
            record.save()
            audit(request, "upload", "success", record.pk)
    except (OSError, InvalidTag, ImproperlyConfigured):
        audit(request, "upload", "failed")
        return HttpResponse("File storage unavailable.", status=503)
    except DatabaseError:
        return HttpResponse("File storage unavailable.", status=503)
    return redirect("files")


@login_required
@require_POST
def download(request, file_id):
    record = owned_file(request, file_id, "download")
    try:
        data = crypto.decrypt(record)
    except (InvalidTag, OSError, ValueError, ImproperlyConfigured):
        audit(request, "download", "integrity-failure", file_id)
        return HttpResponse("File unavailable.", status=409)
    response = HttpResponse(data, content_type="application/octet-stream")
    response["Content-Disposition"] = content_disposition_header(True, record.name)
    audit(request, "download", "success", file_id)
    return response


@login_required
@require_POST
def rename(request, file_id):
    record = owned_file(request, file_id, "rename")
    form = NameForm(request.POST)
    if not form.is_valid():
        return render(
            request, "core/form.html", {"form": form, "title": "Rename"}, status=400
        )
    try:
        with transaction.atomic():
            if not StoredFile.objects.filter(pk=record.pk, owner=request.user).update(
                name=form.cleaned_data["name"]
            ):
                audit(request, "rename", "denied", file_id)
                return HttpResponse("File not found.", status=404)
            audit(request, "rename", "success", file_id)
    except DatabaseError:
        return HttpResponse("File operation unavailable.", status=503)
    return redirect("files")


@login_required
@require_POST
def delete(request, file_id):
    record = owned_file(request, file_id, "delete")
    try:
        with transaction.atomic():
            size = record.size
            deleted, _ = StoredFile.objects.filter(
                pk=file_id, owner=request.user
            ).delete()
            if deleted:
                Usage.objects.filter(owner=request.user).update(used=F("used") - size)
                audit(request, "delete", "success", file_id)
    except DatabaseError:
        return HttpResponse("File operation unavailable.", status=503)
    return redirect("files")
