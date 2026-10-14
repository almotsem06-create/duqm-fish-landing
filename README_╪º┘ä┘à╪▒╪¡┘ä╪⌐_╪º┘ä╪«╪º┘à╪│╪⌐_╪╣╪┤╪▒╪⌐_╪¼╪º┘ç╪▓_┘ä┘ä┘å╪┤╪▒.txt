نظام تسجيل إنزال الأسماك في الدقم — نسخة مهيأة للنشر

التشغيل المحلي:
1) python -m venv .venv
2) تفعيل البيئة الافتراضية
3) pip install -r requirements.txt
4) تعيين SECRET_KEY بقيمة عشوائية قوية
5) python app.py أو gunicorn wsgi:app

النشر:
- يمكن استخدام Dockerfile مع Render أو أي خدمة تدعم Docker.
- يجب ضبط SECRET_KEY في متغيرات البيئة.
- DATA_DIR=/var/data عند استخدام قرص دائم.
- COOKIE_SECURE=1 عند تشغيل HTTPS.

تنبيه:
هذه النسخة تستخدم SQLite، ولذلك يجب تشغيلها بمثيل واحد مع تخزين دائم. للتوسع إلى عدة مثيلات يُنصح بالانتقال إلى PostgreSQL وتخزين خارجي للمرفقات.
الحسابات التجريبية: admin/admin123 و inspector/inspect123 و viewer/view123 — يجب تغييرها فورًا بعد أول دخول.
