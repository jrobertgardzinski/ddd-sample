# Aggregate

## User

* userId
* email
* password
* ticket

# Commands and Events

## Requiring persistence

1. **Register**
   1. Registered a new user
   2. A user with the given e-mail already exists
2. **Authenticate**
   1. User authenticated successfully
   2. Failed to authenticate
   3. Failed to authenticate n-times (block authentication)
   4. Authentication blocked

*-room to improve: Authenticate from known machine and Authenticate from a new machine

### Requiring persistence and EmailService

1. **Ask for the password reset link and send it via e-mail**
   1. Reset link sent
      1. **Reset the password from the password reset link**
         1. Password reset successfully
         2. Reset link expired
