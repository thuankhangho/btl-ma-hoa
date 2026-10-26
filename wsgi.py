"""
Điểm vào WSGI cho Gunicorn (chạy production / systemd):

    gunicorn --bind 127.0.0.1:8000 wsgi:app

`python app.py` chỉ dùng web server phát triển của Flask, không dùng để chạy dịch vụ.
"""
from app import app  # noqa: F401
