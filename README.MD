### This is a simple project to learn more about Spring Security using Jason Web Tokens.

The goals are to learn more about access token and refresh token using cookies, filters, project organization in general
when adding
authentication.

This project is just for **educational** porposes.

**This project has the following endpoints:**

- **GET** /admin
    - Requires authorization;
    - Only users with ADMIN role has access;
- **GET** /user
    - Requires authorization;
    - Any user has access;
- **POST** /auth/sign-in
    - No requires authorization;
    - Requires email and password on request body;
    - Returns a response with JSON with the access token and a cookie with the refresh token;
- **POST** /auth/logout
    - Requires authorization;
    - Remove refresh token cookie data from response;
- **GET** /auth/refresh
    - No requires authorization but requires the refresh token cookie;
    - Returns a response with JSON with the access token; 