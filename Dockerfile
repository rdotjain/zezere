FROM registry.access.redhat.com/ubi8/python-38

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

ENTRYPOINT ["sh", "app.sh"]