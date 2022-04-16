# Setup a zezere instance locally

1. To install requirements in a Python virtual environment, set it up first.
    ```sh
    $ virtualenv venv
    $ . venv/bin/activate
    ```

2. Before installing other Python requirements, you need to install Apache httpd first. Follow the instructions from [mod-wsgi project documentation](https://pypi.org/project/mod-wsgi/).
<br>
In order to satisfy the `psycopg2` dependency please follow instructions from
 [psycopg2 project documentation](https://www.psycopg.org/docs/install.html).

3. Install the requirements
    ```sh
    $ (venv) pip install .
    ```

4. Before using the `zezere-manage` tool, a configuration needs to be created.
 Default configuration can be used as a base:

    ```
    $ cp zezere/default.conf ./zezere.conf
    ```

5. Authentication method and secret key needs to be set in order to satisfy the
 tool. Also, make sure that the allowed_hosts is what you want.

    ```
    allowed_hosts = localhost, 127.0.0.1
    secret_key = very-secret
    auth_method = local
    ```

6. Now run the migrations, to create a database file.
    ```sh
    $ python manage.py migrate --noinput
    ```

7. To collect the static files, run
    ```
    $ python manage.py collectstatic
    ```

8. Now we can create a superuser:

    ```
    $ zezere-manage createsuperuser --username admin --email user@domain.tld
    ```

9. After a password has been set, we are ready to run Zezere:

    ```
    ./app.sh
    ```

    Use the admin credentials we created to login to localhost:8080

<br>

# Setup using Docker
The easiest way to run Zezere is to run the official container and authenticate
 with OpenID Connect:

 ```
 $ docker run --detach --rm --name zezere \
     -e OIDC_RP_CLIENT_ID=<client id> \
     -e OIDC_RP_CLIENT_SECRET=<client secret> \
     -e OIDC_OP_AUTHORIZATION_ENDPOINT=<authorization endpoint> \
     -e OIDC_OP_TOKEN_ENDPOINT=<token endpoint> \
     -e OIDC_OP_USER_ENDPOINT=<userinfo endpoint> \
     -e OIDC_OP_JWKS_ENDPOINT=<jwks endpoint> \
     -e AUTH_METHOD=oidc \
     -e SECRET_KEY=localtest \
     -e ALLOWED_HOSTS=localhost \
     -p 8080:8080 \
     -t quay.io/fedora-iot/zezere:latest
 ```

 The default signing algorithm is `RS256` but it can also be controlled with the
 environment variable `OIDC_OP_SIGN_ALGO`