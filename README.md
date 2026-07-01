# jarshield server
hello yes this is my jarshield server how are you
<br>
this is being hosted at: https://jarshield.link/api

## Requirements:
```
Flask
Flask-Cors
python-dotenv
PyJWT
cryptography
requests
gunicorn
```
run `pip install -r requirements.txt` to install these.

## Setup instructions (if you wanna host it yourself)
this version serves to the api subdomain. 
install dependencies with `pip install -r requirements.txt`

### Enviroment config.
database is done using supabase so you gotta put your supabase URL in the enviroment as an `.env` file.
you will also need to set up JWT for logins, put it in the `.env`.
you can follow the things from `.env.example` 👍
