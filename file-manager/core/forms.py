import unicodedata
from pathlib import Path

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError


class RegisterForm(UserCreationForm):
    def clean_password1(self):
        value = self.cleaned_data.get("password1", "")
        if len(value) > 128:
            raise ValidationError("Use at most 128 characters.")
        return value


def validate_name(value):
    if (
        not value.strip()
        or len(value) > 255
        or any(c in "/\\" or unicodedata.category(c).startswith("C") for c in value)
    ):
        raise ValidationError(
            "Use a name of 1–255 characters without paths or control characters."
        )
    return value


def validate_file_name(value):
    validate_name(value)
    if Path(value).suffix.lower() not in {".txt", ".pdf", ".png", ".jpg", ".jpeg"}:
        raise ValidationError(
            "Allowed types: TXT, PDF, PNG and JPEG. Downloads are never previewed."
        )
    return value


class NameForm(forms.Form):
    name = forms.CharField(max_length=255, validators=[validate_file_name])


class UploadForm(forms.Form):
    file = forms.FileField()

    def clean_file(self):
        value = self.cleaned_data["file"]
        validate_file_name(value.name)
        return value
