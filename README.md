# simple-encrypt-api

This is a simple encrypt api by Java with Spring boot.

## What You Need
- About 15 minutes
- A favorite text editor or IDE
- JDK 1.8 or later
- Maven 3.2+
- You can also import the code straight into your IDE:
IntelliJ IDEA

## Installation Guide
- Download and unzip the source repository for this guide, or clone it using Git: 
```bash
git clone https://github.com/nicoletangsy/simple-encrypt-api.git
```
then run the following command in a terminal window:
```bash
./mvnw spring-boot:run
```

## Encrypt and Decrypt
Make a post request for encryption:
- Encrypt:
http://localhost:8080/aes/encrypt

- Decrypt:
http://localhost:8080/aes/decrypt

Use postman to send request:
import encryption.postman_collection.json in POSTMAN
Input parameters in Body form-data:
- Encrypt:
```bash
plain_text:Apple
aes_key:404D635166546A576E5A723475377721
```
- Decrypt:
```bash
cipher_text:C9E461E80EC3047944ACAE96A9896BC3
aes_key:404D635166546A576E5A723475377721
```