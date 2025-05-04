
# 📦 Repo-Scanner Helm Chart

This Helm chart deploys the **Repo Scanner** system on Kubernetes. It includes the Flask-based web app, scanning workers, webhook workers, a scheduler, and an optional RabbitMQ instance.

---

## 🧭 Features

- **Configurable component replicas** (web, worker, webhook, scheduler)
- **Built-in RabbitMQ** (optional)
- **Persistent volume support**
- **Support for Git webhook, scheduled scanning, and multi-scanner jobs**
- **Ingress support**
- **Secrets separation with `values-secret.yaml`**

---

## 🚀 Quick Start

```bash
helm install repo-scanner ./Helm \
  -f values.yaml \
  -f values-secret.yaml \
  --namespace repo-scanner
```

---

## ⚙️ Configuration Options

### ✅ General

| Key         | Description                            | Example |
|--------------|----------------------------------------|---------|
| `db_init`     | Run DB initialization on first web pod | `true`  |

---

### 🐳 Image

| Key                | Description             | Default                     |
|--------------------|-------------------------|-----------------------------|
| `image.repository` | Docker image to deploy  | `bennoli13/repo-scanner`    |
| `image.tag`        | Image version tag       | `v1.0.0`                    |
| `image.pullPolicy` | Image pull policy       | `IfNotPresent`              |

---

### 🧬 Replica Counts

| Component        | Key                        | Example |
|------------------|-----------------------------|---------|
| Web App          | `replicaCount.web`          | `1`     |
| Master Worker    | `replicaCount.worker.master`| `1`     |
| Child Workers    | `replicaCount.worker.child` | `3`     |
| Webhook Workers  | `replicaCount.webhookWorker`| `2`     |
| Scheduler        | `replicaCount.scheduler`    | `1`     |

---

### 🌿 Environment Variables (`env` block)

| Variable          | Description                             | Example                                                   |
|-------------------|-----------------------------------------|-----------------------------------------------------------|
| `FLASK_ENV`       | Flask environment                       | `production`                                              |
| `RABBITMQ_HOST`   | RabbitMQ service hostname               | `repo-scanner-rabbitmq.repo-scanner.svc.cluster.local`    |
| `API_BASE`        | Internal URL of web service             | `http://repo-scanner-web.repo-scanner.svc.cluster.local:5000` |

---

### 🌐 Service and Ingress

| Key                | Description                | Example                    |
|--------------------|----------------------------|----------------------------|
| `service.type`     | Service type for Flask web | `ClusterIP`                |
| `service.port`     | Port to expose web         | `5000`                     |
| `ingress.enabled`  | Enable Ingress             | `true`                     |
| `ingress.className`| Ingress class              | `nginx-internal`           |
| `ingress.host`     | Public DNS to route traffic| `repo-scanner.internal`    |

---

### 🐰 RabbitMQ

| Key                | Description         | Example                |
|--------------------|---------------------|------------------------|
| `rabbitmq.enabled` | Deploy RabbitMQ     | `true`                 |
| `rabbitmq.image`   | RabbitMQ image      | `rabbitmq:3-management`|

---

### 💾 Persistent Volume

| Key                      | Description              | Example     |
|--------------------------|--------------------------|-------------|
| `persistence.enabled`    | Enable volume for DB      | `true`      |
| `persistence.size`       | Volume size              | `5Gi`       |
| `persistence.storageClass`| Storage class           | `gp3-retain`|

---

### ⚙️ Worker Resources

```yaml
worker:
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
```

---

## 🔐 values-secret.yaml

Store secrets separately in `values-secret.yaml` to keep them out of Git.

```yaml
secret:
  DATABASE_URI: "postgresql://user:password@host:5432/db"
  RABBITMQ_USER: "myuser"
  RABBITMQ_PASS: "mypassword"
  FERNET_KEY: "a-32-byte-base64-key"
```

Use with:

```bash
helm install repo-scanner ./Helm -f values.yaml -f values-secret.yaml
```

---

## 📁 Folder Structure

```
Helm/
  ├── templates/
  ├── values.yaml
  ├── values-secret.yaml
  └── Chart.yaml
```
