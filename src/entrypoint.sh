#!/bin/sh

# Start Cron Service
sudo service cron start

# Collect static files
# echo "Collecting static files...."
# python manage.py collectstatic --noinput || exit 1

# Apply database migrations
echo "Apply database migrations"
python manage.py migrate

python manage.py crontab add

python manage.py crontab add

# Start server
echo "Starting server"

gunicorn core.wsgi:application --bind 0.0.0.0:8000