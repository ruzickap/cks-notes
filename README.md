# CKS Notes

Handy notes can be also find here: [https://github.com/dragon7-fc/misc/tree/1385c4a2e4719b9aa914c3b274c2877f7305d11e](https://github.com/dragon7-fc/misc/tree/1385c4a2e4719b9aa914c3b274c2877f7305d11e)

## Test k8s cluster using Vagrant

Prepare the test environment - Kubernetes cluster with 1 master node and one
worker node using Vagrant + VirtualBox:

```bash
git clone git@github.com:kodekloudhub/certified-kubernetes-administrator-course.git

cd certified-kubernetes-administrator-course || exit
sed -i 's/NUM_WORKER_NODE = 2/NUM_WORKER_NODE = 1/' Vagrantfile

vagrant up
```

Run on both k8s nodes (`kubemaster`, `kubenode01`):

```bash
# vagrant ssh kubemaster
# vagrant ssh kubenode01

cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sudo sysctl --system

sudo apt-get update

sudo apt-get install -y apt-transport-https ca-certificates curl jq lsb-release mc tree

sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF

sudo usermod -aG docker "${USER}"

sudo systemctl enable docker
sudo systemctl daemon-reload
sudo systemctl restart docker

sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

cat >> ~/.bashrc << EOF
source <(kubectl completion bash)
alias k=kubectl
EOF
```

Run on **master** `kubemaster` node only:

```bash
# vagrant ssh kubemaster

sudo kubeadm init --pod-network-cidr=10.224.0.0/16 --apiserver-advertise-address=192.168.56.2

mkdir -p "${HOME}/.kube"
sudo cp -i /etc/kubernetes/admin.conf "${HOME}/.kube/config"
sudo chown "$(id -u):$(id -g)" "${HOME}/.kube/config"

curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
cilium install
```

Run on **worker** `kubenode01` node only:

```bash
# vagrant ssh kubenode01
sudo kubeadm join 192.168.56.2:6443 --token i0sn6a.jnvsbw73yi03nre7 --discovery-token-ca-cert-hash sha256:ffa3c5c3cd8ee55bd9497e8d6d9556d3bcef7b0879f871a088819f232c4673e0
```

## Kubernetes certificates

* `/etc/kubernetes/pki`
* `/var/lib/kubelet/pki`

```text
$ sudo tree /etc/kubernetes/pki
/etc/kubernetes/pki
├── apiserver-etcd-client.crt
├── apiserver-etcd-client.key
├── apiserver-kubelet-client.crt
├── apiserver-kubelet-client.key
├── apiserver.crt
├── apiserver.key
├── ca.crt
├── ca.key
├── etcd
│   ├── ca.crt
│   ├── ca.key
│   ├── healthcheck-client.crt
│   ├── healthcheck-client.key
│   ├── peer.crt
│   ├── peer.key
│   ├── server.crt
│   └── server.key
├── front-proxy-ca.crt
├── front-proxy-ca.key
├── front-proxy-client.crt
├── front-proxy-client.key
├── sa.key
└── sa.pub

$ sudo tree /var/lib/kubelet/pki
/var/lib/kubelet/pki
├── kubelet-client-2021-10-09-07-44-38.pem
├── kubelet-client-current.pem -> /var/lib/kubelet/pki/kubelet-client-2021-10-09-07-44-38.pem
├── kubelet.crt
└── kubelet.key
```

## Docker namespace

```bash
docker run --name cont1 -d ubuntu sh -c "sleep 1d"
docker run --name cont2 --pid=container:cont1 -d ubuntu sh -c "sleep 111d"
```

```text
$ docker exec cont2 ps -elf
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 -   653 do_wai 09:59 ?        00:00:00 sh -c sleep 1d
0 S root         7     1  0  80   0 -   628 hrtime 09:59 ?        00:00:00 sleep 1d
4 S root         8     0  0  80   0 -   653 do_wai 09:59 ?        00:00:00 sh -c sleep 111d
0 S root        15     8  0  80   0 -   628 hrtime 09:59 ?        00:00:00 sleep 111d
4 R root        16     0  0  80   0 -  1475 -      10:00 ?        00:00:00 ps -elf

$ docker exec cont1 ps -elf
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 -   653 do_wai 09:59 ?        00:00:00 sh -c sleep 1d
0 S root         7     1  0  80   0 -   628 hrtime 09:59 ?        00:00:00 sleep 1d
4 S root         8     0  0  80   0 -   653 do_wai 09:59 ?        00:00:00 sh -c sleep 111d
0 S root        15     8  0  80   0 -   628 hrtime 09:59 ?        00:00:00 sleep 111d
4 R root        22     0  0  80   0 -  1475 -      10:00 ?        00:00:00 ps -elf
```

## Network Policies

[Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

Run two test pods + services:

```bash
kubectl run frontend --image=nginx --port=80 --expose=true
kubectl run backend --image=nginx --port=80 --expose=true
kubectl create namespace database
kubectl label namespace database ns=database
kubectl run -n database database --image=nginx --port=80 --expose=true
```

Check connectivity:

```bash
kubectl exec frontend -- curl -s backend
kubectl exec backend -- curl -s frontend
kubectl exec backend -- curl -s database.database.svc.cluster.local
```

Deny all policy:

```bash
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
```

Allow connection between `frontend` -> `backend` (and DNS):

```bash
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend
  namespace: default
spec:
  podSelector:
    matchLabels:
      run: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          run: backend
  # DNS - allow by default
  - to:
    ports:
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend
  namespace: default
spec:
  podSelector:
    matchLabels:
      run: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          run: frontend
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          ns: database
  # DNS - allow by default
  - to:
    ports:
      - port: 53
        protocol: UDP
      - port: 53
        protocol: TCP
EOF
```

The following command will work, because there is no NetworkPolicies in the
database namespace.

```bash
kubectl exec backend -- curl -s database.database.svc.cluster.local
```

## Kubernetes Dashboard

[Dashboard arguments](https://github.com/kubernetes/dashboard/blob/master/docs/common/dashboard-arguments.md)

> Do not do this on your production :-)

Install:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml
```

Create `ClusterRoleBinding`:

```bash
kubectl create clusterrolebinding kubernetes-dashboard-view-all --serviceaccount kubernetes-dashboard:kubernetes-dashboard --clusterrole view
```

Configure `NodePort` "access":

```bash
kubectl patch svc -n kubernetes-dashboard kubernetes-dashboard --type='json' -p '[{"op":"replace","path":"/spec/type","value":"NodePort"}]'
```

Edit configuration by running
`kubectl edit deploy -n kubernetes-dashboard kubernetes-dashboard`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
...
spec:
...
  template:
    spec:
      containers:
      - args:
        # - --auto-generate-certificates     # Allow use port 9090 for insecure HTTP connections
        - --namespace=kubernetes-dashboard
        - --authentication-mode=basic        # Enable basic authentication
        - --enable-skip-login=true           # Enable "skip button" on the login page will be shown
        - --enable-insecure-login            # Enable Dashboard login when using HTTP
...
```

You should be able to reach Kubernetes Dashboard by going to [http://192.168.56.2:32645](http://192.168.56.2:32645):

```bash
curl -k http://192.168.56.2:32645
```

## Ingress

Install `ingress-nginx` and delete "NetworkPolicies" + "Services" + "Pods":

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.0.3/deploy/static/provider/baremetal/deploy.yaml
kubectl delete networkpolicies,svc,pods --all
```

```text
$ kubectl get pods,svc -n ingress-nginx
NAME                                            READY   STATUS              RESTARTS   AGE
pod/ingress-nginx-admission-create--1-hb24s     0/1     Completed           0          13s
pod/ingress-nginx-admission-patch--1-znw8z      0/1     Completed           0          13s
pod/ingress-nginx-controller-6c68f5b657-wzbx8   0/1     ContainerCreating   0          13s

NAME                                         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
service/ingress-nginx-controller             NodePort    10.96.253.251   <none>        80:32550/TCP,443:31606/TCP   13s
service/ingress-nginx-controller-admission   ClusterIP   10.100.6.131    <none>        443/TCP                      13s
```

Verify the `ingress-nginx` is up by running (you will get "404"):

```bash
curl -kv http://192.168.56.2:32550 https://192.168.56.2:31606
```

Start two applications:

```bash
kubectl run app1 --image=ghcr.io/stefanprodan/podinfo:6.0.0 --port=9898 --expose=true --env="PODINFO_UI_MESSAGE=app1"
kubectl run app2 --image=ghcr.io/stefanprodan/podinfo:6.0.0 --port=9898 --expose=true --env="PODINFO_UI_MESSAGE=app2"
```

```bash
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: "nginx"
  rules:
  - http:
      paths:
      - path: /app1
        pathType: Prefix
        backend:
          service:
            name: app1
            port:
              number: 9898
      - path: /app2
        pathType: Prefix
        backend:
          service:
            name: app2
            port:
              number: 9898
EOF
```

You should be able to reach the ingress and the services behind which should
give different response:

```text
$ curl -sk https://192.168.56.2:31606/app1 | jq
{
  "hostname": "app1",
  "version": "6.0.0",
  "revision": "",
  "color": "#34577c",
  "logo": "https://raw.githubusercontent.com/stefanprodan/podinfo/gh-pages/cuddle_clap.gif",
  "message": "app1",
  "goos": "linux",
  "goarch": "amd64",
  "runtime": "go1.16.5",
  "num_goroutine": "6",
  "num_cpu": "2"
}

$ curl -sk https://192.168.56.2:31606/app2 | jq
{
  "hostname": "app2",
  "version": "6.0.0",
  "revision": "",
  "color": "#7c4134",
  "logo": "https://raw.githubusercontent.com/stefanprodan/podinfo/gh-pages/cuddle_clap.gif",
  "message": "app2",
  "goos": "linux",
  "goarch": "amd64",
  "runtime": "go1.16.5",
  "num_goroutine": "6",
  "num_cpu": "2"
}
```

### Ingress - certificate

There is self signed certificate used by Ingress:

```text
$ curl -sk https://192.168.56.2:31606/app2
...
* Server certificate:
*  subject: O=Acme Co; CN=Kubernetes Ingress Controller Fake Certificate
...
```

Generate new cert:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout key.pem -out cert.pem \
-subj /C=CZ/ST=Czech/L=Prague/O=IT/OU=DevOps/CN=my-secure-ingress.k8s.cluster.com
```

Create k8s secret:

```bash
kubectl create secret tls tls-secret --cert=cert.pem --key=key.pem
```

Update ingress:

```bash
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: "nginx"
  tls:
  - hosts:
      - my-secure-ingress.k8s.cluster.com
    secretName: tls-secret
  rules:
  - host: my-secure-ingress.k8s.cluster.com
    http:
      paths:
      - path: /app1
        pathType: Prefix
        backend:
          service:
            name: app1
            port:
              number: 9898
      - path: /app2
        pathType: Prefix
        backend:
          service:
            name: app2
            port:
              number: 9898
EOF
```

```text
$ curl -kv https://my-secure-ingress.k8s.cluster.com:31606/app2 --resolve my-secure-ingress.k8s.cluster.com:31606:192.168.56.2
...
* Server certificate:
*  subject: C=CZ; ST=Czech; L=Prague; O=IT; OU=DevOps; CN=my-secure-ingress.k8s.cluster.com
...
```

## CIS benchmarks

[CIS Kubernetes Benchmark v1.6.0 - 07-23-2020](https://github.com/cismirror/old-benchmarks-archive/blob/master/CIS_Kubernetes_Benchmark_v1.6.0.pdf)

### kube-bench

[kube-bench](https://github.com/aquasecurity/kube-bench)

```bash
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -v "$(which kubectl):/usr/local/mount-from-host/bin/kubectl" -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config -t aquasec/kube-bench:latest master
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -v "$(which kubectl):/usr/local/mount-from-host/bin/kubectl" -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config -t aquasec/kube-bench:latest node
```

## Hashes

* Get kubernetes binaries from: [Kubernetes v1.22.2](https://github.com/kubernetes/kubernetes/releases/tag/v1.22.2)

* Go to [CHANGELOG](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.22.md)

* Check [Downloads for v1.22.2](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.22.md#downloads-for-v1222)

Generate SHA512 hash from the file:

```bash
curl -L https://dl.k8s.io/v1.22.2/kubernetes-server-linux-amd64.tar.gz | sha512sum
```

## RBAC

[Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

Create namespace `red` and `blue`:

```bash
kubectl create namespace red
kubectl create namespace blue
```

Create "Roles" and "RoleBindings":

```bash
kubectl create role secret-manager-role --namespace=red --verb=get --resource=secrets
kubectl create rolebinding secret-manager-rolebinding --namespace=red --role secret-manager-role --user=jane

kubectl create role secret-manager-role --namespace=blue --verb=get,list --resource=secrets
kubectl create rolebinding secret-manager-rolebinding --namespace=blue --role secret-manager-role --user=jane
```

Test "Roles" and "RoleBindings":

```bash
$ kubectl auth can-i get secrets --namespace=red --as jane
yes
$ kubectl auth can-i list secrets --namespace=red --as jane
no
$ kubectl auth can-i list secrets --namespace=blue --as jane
yes
```

Create "ClusterRoles" and "ClusterRoleBindings":

```bash
kubectl create clusterrole deploy-deleter --verb=delete --resource=deployments
kubectl create clusterrolebinding deploy-deleter --user=jane --clusterrole=deploy-deleter
```

Test "ClusterRoles" and "ClusterRoleBindings":

```bash
kubectl auth can-i delete deployments --as jane --all-namespaces
yes
```

## Users and Certificates

[Certificate Signing Requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)

Create Jane's certificate:

```bash
touch ~/.rnd
openssl genrsa -out jane.key 2048
openssl req -new -key jane.key -out jane.csr \
-subj /C=CZ/ST=Czech/L=Prague/O=IT/OU=DevOps/CN=jane
```

Create `CertificateSigningRequest`:

```bash
kubectl apply -f - << EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: jane
spec:
  groups:
  - system:authenticated
  request: $(base64 -w0 jane.csr)
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF
```

Check certs:

```text
$ kubectl get certificatesigningrequest
NAME   AGE   SIGNERNAME                            REQUESTOR          REQUESTEDDURATION   CONDITION
jane   86s   kubernetes.io/kube-apiserver-client   kubernetes-admin   <none>              Pending

$ kubectl certificate approve jane
NAME   AGE   SIGNERNAME                            REQUESTOR          REQUESTEDDURATION   CONDITION
jane   95s   kubernetes.io/kube-apiserver-client   kubernetes-admin   <none>              Approved,Issued
```

Save signed Jane's certificate to file and create context:

```bash
kubectl get certificatesigningrequest jane -o=jsonpath='{.status.certificate}' | base64 -d > jane.crt
kubectl config set-credentials jane --client-key=jane.key --client-certificate=jane.crt --embed-certs=true
kubectl config set-context jane --user=jane --cluster=kubernetes
```

```text
$ kubectl config get-contexts
CURRENT   NAME                          CLUSTER      AUTHINFO           NAMESPACE
          jane                          kubernetes   jane
*         kubernetes-admin@kubernetes   kubernetes   kubernetes-admin

$ kubectl config use-context jane
Switched to context "jane".

$ kubectl get pods
Error from server (Forbidden): pods is forbidden: User "jane" cannot list resource "pods" in API group "" in the namespace "default"

$ kubectl get secrets -n blue
NAME                  TYPE                                  DATA   AGE
default-token-g7sgk   kubernetes.io/service-account-token   3      3h51m
```
