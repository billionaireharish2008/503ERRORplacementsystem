# Layer 1 setup (Django 5.1 or newer)

```bash
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install "django>=5.1"
django-admin startproject config .
python manage.py startapp core      # then REPLACE core/models.py, admin.py, tests.py
                                    # and copy core/management/ from this folder
```

Edit `config/settings.py`:
```python
INSTALLED_APPS += ["core"]
DEBUG = True        # only for development; must be False in deployment
# Quick start uses SQLite. For a realistic prototype switch DATABASES to PostgreSQL
# and read the password from an environment variable, never from the code.
```

Run:
```bash
python manage.py makemigrations core
python manage.py migrate
python manage.py test               # Layer 1 gate tests
python manage.py createsuperuser
python manage.py seed_demo          # 40 synthetic students
python manage.py runserver          # open /admin
```

CSV import (header must be `placement_id,full_name,mobile,email,programme_code,batch_label`):
```bash
python manage.py import_students students.csv --dry-run
python manage.py import_students students.csv
```
