## **1. Create .env**

_Copy .env.examplefordocker-compose and rename to .env_

## **2. Docker Compose Build and RUN**

```commandline
docker-compose up -d --build --force-recreate
```

### **Working With Docker Images**

#### **1. To See All the Images**

```commandline
docker images
```

#### **2. To Remove a Docker Image**

```commandline
docker rmi image_name:image_tag
```

### **Working with Docker Containers**

#### **_1. To Use the Container Shell_**

```commandline
docker exec -it container_name bash
```

_Example:_

```commandline
docker exec -it backend bash
```

#### **_2. To View All Containers_**

```commandline
docker ps -a
```

#### **_3. To See All Docker Containers Status_**

```commandline
docker stats
```

#### **_4. To Inspect Specific Docker Containers_**

```commandline
docker inspect container_name
```

#### **_5. To Stop Specific Container_**

```commandline
docker stop container_name
```

#### **_6. To Remove Specific Container (Only After No 5)_**

```commandline
docker rm container_name
```
