from core import views
from django.urls import path

urlpatterns = [
    path("", views.index, name="index"),
    path("health/", views.health, name="health"),
    path("auth/register/", views.register, name="register"),
    path("auth/login/", views.sign_in, name="login"),
    path("auth/logout/", views.sign_out, name="logout"),
    path("files/", views.files, name="files"),
    path("files/upload/", views.upload, name="upload"),
    path("files/<uuid:file_id>/download/", views.download, name="download"),
    path("files/<uuid:file_id>/rename/", views.rename, name="rename"),
    path("files/<uuid:file_id>/delete/", views.delete, name="delete"),
]
