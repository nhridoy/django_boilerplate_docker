<div align="center">

![Oxygen - An API Ready starter boilerplate with Django and Django Rest Framework](https://img.icons8.com/external-flaticons-lineal-color-flat-icons/256/FA5252/external-oxygen-diving-flaticons-lineal-color-flat-icons-2.png)

<h1 style="color: #ff56ff;">Oxygen</h1>

<p style="font-size: 1.5rem">An API Ready starter boilerplate with Django and Django Rest Framework</p>

[![Django Test](https://github.com/nhridoy/oxygen/actions/workflows/django.yml/badge.svg)](https://github.com/nhridoy/oxygen/actions/workflows/django.yml)
[![Black](https://github.com/nhridoy/oxygen/actions/workflows/black.yml/badge.svg)](https://github.com/nhridoy/oxygen/actions/workflows/black.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

</div>

## Features

- Login/Registration/Logout
- JWT Based Authentication
- Session Based Authentication
- Cookie Based Authentication
- Customized User Model
- OTP Based Login System
- Email Verification
- Docker Ready

## Endpoints

1. Login: (Two Endpoints for currently)

   POST: `account/login/` _OTP is not Supported_

   _Payload:_

   ```json
   {
     "email": "",
     "password": ""
   }
   ```

   _Response: 200_

   ```json
   {
     "access_token": "",
     "refresh_token": "",
     "user": {
       "pk": 1,
       "email": ""
     }
   }
   ```

   POST: `account/token/` _OTP is Supported, Session Authentication Supported_

   _Payload:_

   ```json
   {
     "email": "",
     "password": ""
   }
   ```

   _Response: 200_

   ```json
   {
     "refresh": "",
     "access": ""
   }
   ```

2. Resigtration:

   POST: `account/registration/`

   _Payload:_

   ```json
   {
     "email": "",
     "username": "",
     "password1": "",
     "password2": ""
   }
   ```

   _Response:_

   ```json

   ```

3. Logout: _Only for Cookie Based Authentication_

   POST: `account/logout/`

   _Payload:_

   ```json

   ```

   _Response: 401_

   ```json
   {
     "detail": "Refresh token was not included in request data."
   }
   ```

4. Password Change:
5. Forget Password:
6. Validate Password:
7. Activate OTP:
8. Login With OTP:
9. Email Verification:
10. etc.

## Run Project

To Run this project [View This Documentation](DOCS/README.md)

## Contribution

You can contribute to this project one of the following ways.

### Make improvement

I know that this project has a lot of improvement to do. If you want to make improvement you can fork this project and make a pull request with your improvement.

_N.B. Make sure to provide a good documentation of your pull request._

**NOTE: We use black and isort as code formatter. So while contributing make sure to run below command in your git-bash terminal to activate pre commit**

```bash
bash pre-commit.sh
```

### Give star and share

You can give star to this project and share with your developer friends. So that they can start their next big startup easily from here.

### Buy me a coffee

If you feel generous, you can donate to this project to this following link.

---

**_Contributors:_**

<a href="https://github.com/nhridoy/oxygen/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=nhridoy/oxygen&max=100&columns=12" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

**_Current Donators:_**

## TODO

- Create Better Documentation
- Optimize Code
- Improve the endpoints
- Make single endpoint for login
- Include Social Authentication
- Create a demo frontend
- And More
