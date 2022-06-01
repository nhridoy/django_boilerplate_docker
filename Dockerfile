# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:3.10.4-bullseye

EXPOSE 8000

RUN apt update && apt upgrade && apt install nano

# Install pip requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt
RUN rm requirements.txt

WORKDIR /app
COPY ./src /app

# Creates a non-root user with an explicit UID and adds permission to access the /app folder
# For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser


# During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
ENTRYPOINT ["sh", "entrypoint.sh"]
