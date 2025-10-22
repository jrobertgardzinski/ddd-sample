Consider the following:
- security-micronaut uses security-domain in provided scope
- same for security-password-hash-algorithm
- then introduce some kind of master security module or something that takes all modules as compile scope 
  - security-domain
  - security-micronaut
  - security-password-hash-algorithm