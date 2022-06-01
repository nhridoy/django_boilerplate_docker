## **Working with Docker Images**

### **1. Create .env**

_Copy .env.examplefordjango to src directory and rename to .env_

### **2. Build Docker Image**

```commandline
docker build -t image_name:image_tag .
```

_Example:_

```commandline
docker build -t backend:latest .
```

### **3. To See All the Images**

```commandline
docker images
```

### **4. To Remove a Docker Image**

```commandline
docker rmi image_name:image_tag
```

## **Working with Docker Containers**

### **1. RUN Docker Image**

```commandline
docker run -t -d --name container_name -p external_port:docker_port --restart unless-stopped image_name:image_tag
```

_Example:_

```commandline
docker run -t -d --name backend -p 8000:8000 --restart unless-stopped backend:latest
```

### **_2. To Use the Container Shell_**

```commandline
docker exec -it container_name bash
```

_Example:_

```commandline
docker exec -it backend bash
```

### **_3. To View All Containers_**

```commandline
docker ps -a
```

### **_4. To See All Docker Containers Status_**

```commandline
docker stats
```

### **_5. To Inspect Specific Docker Containers_**

```commandline
docker inspect container_name
```

### **_6. To Stop Specific Container_**

```commandline
docker stop container_name
```

### **_7. To Remove Specific Container (Only After No 5)_**

```commandline
docker rm container_name
```
