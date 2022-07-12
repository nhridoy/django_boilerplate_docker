## **1. Create venv**

```commandline
python -m venv venv
```

## **2. Activate venv**

_For Windows_

```commandline
venv\Scripts\activate
```

_For UNIX_

```bash
source venv\bin\activate
```

## **3. Install Requirements**

```commandline
pip install -r requirements.txt
```

## **4. Navigate to src Directory**

```commandline
cd src
```

## **5. Create .env**

_Copy .env.examplefordjango to src directory and rename to .env_

## **6. Migrate**

```commandline
python manage.py migrate
```

## **7. Create Superuser**

```commandline
python manage.py createsuperuser
```

## **8. Run Server**

```commandline
python manage.py runserver
```
