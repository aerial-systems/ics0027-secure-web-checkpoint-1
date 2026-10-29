from io import BytesIO

from django.conf import settings
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.uploadhandler import FileUploadHandler, StopUpload


class BoundedUploadHandler(FileUploadHandler):
    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        self.buffer = BytesIO()
        self.received = 0

    def receive_data_chunk(self, raw_data, start):
        self.received += len(raw_data)
        if self.received > settings.MAX_FILE_BYTES:
            self.request.upload_too_large = True
            raise StopUpload(connection_reset=True)
        self.buffer.write(raw_data)

    def file_complete(self, file_size):
        self.buffer.seek(0)
        return InMemoryUploadedFile(
            self.buffer,
            self.field_name,
            self.file_name,
            self.content_type,
            file_size,
            self.charset,
        )
