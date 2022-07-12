<center>

![Oxygen - An API Ready starter boilerplate with Django and Django Rest Framework](https://img.icons8.com/external-flaticons-lineal-color-flat-icons/64/FA5252/external-oxygen-diving-flaticons-lineal-color-flat-icons-2.png)

<b style="color: #ff56ff; font-size: 2rem;">Oxygen</b>

<p style="font-size: 1.5rem">An API Ready starter boilerplate with Django and Django Rest Framework</p>
</center>

# Oxygen

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

   POST: `account/login/` _OTP is not Supported, Session Authentication Supported_

   ```json
       "email": "",
       "password": ""
   ```

   POST: `account/token/` _OTP is Supported, Session Authentication Not Supported_

   ```json
       "email": "",
       "password": ""
   ```

2. Resigtration:

   POST: `account/registration/`

   ```json
      "email": "",
      "username": "",
      "password1": "",
      "password2": ""
   ```

3. Logout: _Only for Cookie Based Authentication_

   POST: `account/logout/`

   ```json

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

### Give star and share

You can give star to this project and share with your developer friends. So that they can start their next big startup easily from here.

### Buy me a coffee

If you feel generous, you can donate to this project to this following link.

---

**_Current Donators:_**

## TODO

- Create Better Documentation
- Optimize Code
- Improve the endpoints
- Make single endpoint for login
- Include Social Authentication
- Create a demo frontend
- And More
