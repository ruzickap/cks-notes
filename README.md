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

The installation is taken from: [install_master.sh](https://github.com/killer-sh/cks-course-environment/blob/master/cluster-setup/latest/install_master.sh)

Run on both k8s nodes (`kubemaster`, `kubenode01`):

```bash
# vagrant ssh kubemaster
# vagrant ssh kubenode01

KUBE_VERSION=1.21.5

sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates containerd curl docker.io etcd-client jq lsb-release mc tree

cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system

sudo mkdir -p /etc/containerd
containerd config default | sed 's/SystemdCgroup = false/SystemdCgroup = true/' | sudo tee /etc/containerd/config.toml
sudo systemctl restart containerd

cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF

sudo usermod -aG docker "${USER}"

sudo systemctl daemon-reload
sudo systemctl enable containerd docker
sudo systemctl restart containerd

sudo apt-get install -y kubelet=${KUBE_VERSION}-00 kubeadm=${KUBE_VERSION}-00 kubectl=${KUBE_VERSION}-00
sudo apt-mark hold kubelet kubeadm kubectl

cat >> ~/.bashrc << EOF
source <(kubectl completion bash)
alias k=kubectl
complete -F __start_kubectl k
EOF
```

Run on **master** `kubemaster` node only:

```bash
# vagrant ssh kubemaster

sudo kubeadm init --cri-socket /run/containerd/containerd.sock --kubernetes-version=${KUBE_VERSION} --pod-network-cidr=10.224.0.0/16 --apiserver-advertise-address=192.168.56.2 --skip-token-print

mkdir -p "${HOME}/.kube"
sudo cp -i /etc/kubernetes/admin.conf "${HOME}/.kube/config"
sudo chown "$(id -u):$(id -g)" "${HOME}/.kube/config"

curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
cilium install

kubeadm token create --print-join-command --ttl 0
```

Run on **worker** `kubenode01` node only:

```bash
# vagrant ssh kubenode01
sudo kubeadm join --cri-socket /run/containerd/containerd.sock --kubernetes-version=${KUBE_VERSION} 192.168.56.2:6443 --token i0sn6a.jnvsbw73yi03nre7 --discovery-token-ca-cert-hash sha256:ffa3c5c3cd8ee55bd9497e8d6d9556d3bcef7b0879f871a088819f232c4673e0
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
kubectl patch service -n kubernetes-dashboard kubernetes-dashboard --type='json' -p '[{"op":"replace","path":"/spec/type","value":"NodePort"}]'
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
kubectl delete networkpolicies,service,pods --all
```

```text
$ kubectl get pods,service -n ingress-nginx
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

## Service Accounts

It is a good practice for application to have it's own ServiceAccount.

```text
$ kubectl get serviceaccount,secrets
NAME                     SECRETS   AGE
serviceaccount/default   1         28h

NAME                         TYPE                                  DATA   AGE
secret/default-token-rxnbt   kubernetes.io/service-account-token   3      28h

$ kubectl describe serviceaccounts default
Name:                default
Namespace:           default
Labels:              <none>
Annotations:         <none>
Image pull secrets:  <none>
Mountable secrets:   default-token-rxnbt
Tokens:              default-token-rxnbt
Events:              <none>
```

Create `ServiceAccount` and run the pod using it:

```bash
kubectl create serviceaccount nginx

kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  serviceAccountName: nginx
  containers:
  - image: nginx
    name: nginx
EOF
```

Get into the pod:

```text
$ kubectl exec -it nginx -- bash

$ mount | grep serviceaccount
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime,size=1938344k)

$ find /run/secrets/kubernetes.io/serviceaccount
/run/secrets/kubernetes.io/serviceaccount
/run/secrets/kubernetes.io/serviceaccount/..data
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/ca.crt
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/..2021_10_10_12_32_28.152125108
/run/secrets/kubernetes.io/serviceaccount/..2021_10_10_12_32_28.152125108/token
/run/secrets/kubernetes.io/serviceaccount/..2021_10_10_12_32_28.152125108/namespace
/run/secrets/kubernetes.io/serviceaccount/..2021_10_10_12_32_28.152125108/ca.crt
```

### Disable automount of the ServiceAccount token in the pod

[Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

```yaml
automountServiceAccountToken: false
```

## API Access

By default the k8s API accepts the "anonymous requests". Access is deied for
`system:anonymous` user:

```text
$ curl -k https://localhost:6443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {

  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {

  },
  "code": 403
}
```

Disable anonymous API requests:

```text
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
...
- --anonymous-auth=false
...
```

```text
$ curl -k https://localhost:6443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {

  },
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

Put it back, because `kube-apiserver` needs anonymous API requests for it's own
livenes probes.

### Manual API request using curl

Extract data from "kubeconfig" file:

```bash
kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="kubernetes")].cluster.certificate-authority-data}' | base64 -d > ca
kubectl config view --raw -o jsonpath='{.users[?(@.name=="kubernetes-admin")].user.client-certificate-data}' | base64 -d > crt
kubectl config view --raw -o jsonpath='{.users[?(@.name=="kubernetes-admin")].user.client-key-data}' | base64 -d > key
SERVER=$(kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="kubernetes")].cluster.server}')
echo "${SERVER}"
```

Access the k8s cluster using certificates and ca:

```text
$ curl -s "${SERVER}" --cacert ca --cert crt --key key | jq
{
  "paths": [
    "/.well-known/openid-configuration",
...
    "/version"
  ]
}
```

### Eneble k8s API for external access

[Controlling Access to the Kubernetes API](https://kubernetes.io/docs/concepts/security/controlling-access/)

Verify which IP addresses are allowed to connect to k8s API. You should see your
external IP there `192.168.56.2`:

```text
$ openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text
...
X509v3 Subject Alternative Name:
                DNS:kubemaster, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, IP Address:10.96.0.1, IP Address:192.168.56.2
...
```

Check the kubernetes service:

```text
$ kubectl get service kubernetes
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP   37h
```

Change the service to `NodePort`

```bash
kubectl patch service kubernetes --type='json' -p '[{"op":"replace","path":"/spec/type","value":"NodePort"}]'
```

Find the "NodePort" port which is accessible externally:

```text
$ kubectl get service kubernetes
NAME         TYPE       CLUSTER-IP   EXTERNAL-IP   PORT(S)         AGE
kubernetes   NodePort   10.96.0.1    <none>        443:32689/TCP   37h
```

Copy the kubeconfig to the machine where you are running the vagrant:

```bash
vagrant ssh kubemaster -c "kubectl config view --raw" > local.conf
```

Replace the server parameter with the external IP and "NodePort port:

```bash
sed -i 's@\(.*server: https:\).*@\1//192.168.56.2:32689@' local.conf
```

Check if you can see the namespaces:

```bash
kubectl --kubeconfig=local.conf get ns
```

## Kubernetes cluster upgrade

[Upgrading kubeadm clusters](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)

### Upgrade master node

You are running outdated k8s version 1.19:

```text
# vagrant ssh kubemaster

$ kubectl get nodes
NAME         STATUS   ROLES    AGE   VERSION
kubemaster   Ready    master   22m   v1.19.0
kubenode01   Ready    <none>   22m   v1.19.0
```

Drain the master node:

```bash
kubectl drain kubemaster --ignore-daemonsets
```

The master node is drained:

```bash
$ kubectl get nodes
NAME         STATUS                     ROLES    AGE   VERSION
kubemaster   Ready,SchedulingDisabled   master   25m   v1.19.0
kubenode01   Ready                      <none>   24m   v1.19.0
```

Check avaiable k8s versions (next minor version is 1.20):

```text
$ apt-cache show kubeadm | grep '1.20'
Version: 1.20.11-00
Filename: pool/kubeadm_1.20.11-00_amd64_1343a8b5f81f535549d498a9cf38a2307eee0fc99ea64046b043efae50e31bfe.deb
Version: 1.20.10-00
Filename: pool/kubeadm_1.20.10-00_amd64_bef04cc2cb819b1298bd1c22bae9ba90c52cf581584f5f24871df8447ae93186.deb
...
```

Upgrade k8s cluster components:

```bash
KUBE_VERSION=1.20.10
sudo apt-get install -y --allow-change-held-packages kubelet=${KUBE_VERSION}-00 kubeadm=${KUBE_VERSION}-00 kubectl=${KUBE_VERSION}-00
```

Check the "upgrade plan":

```text
$ kubeadm upgrade plan
...
Components that must be upgraded manually after you have upgraded the control plane with 'kubeadm upgrade apply':
COMPONENT   CURRENT        AVAILABLE
kubelet     1 x v1.19.0    v1.20.10
            1 x v1.20.10   v1.20.10

Upgrade to the latest stable version:

COMPONENT                 CURRENT   AVAILABLE
kube-apiserver            v1.19.0   v1.20.10
kube-controller-manager   v1.19.0   v1.20.10
kube-scheduler            v1.19.0   v1.20.10
kube-proxy                v1.19.0   v1.20.10
CoreDNS                   1.7.0     1.7.0
etcd                      3.4.9-1   3.4.13-0

You can now apply the upgrade by executing the following command:

  kubeadm upgrade apply v1.20.10
...
```

Upgrade the k8s cluster to `1.20.10`:

```bash
sudo kubeadm upgrade apply v1.20.10
```

Check the nodes:

```text
$ kubectl get nodes
NAME         STATUS                     ROLES                  AGE   VERSION
kubemaster   Ready,SchedulingDisabled   control-plane,master   42m   v1.20.10
kubenode01   Ready                      <none>                 42m   v1.19.0
```

Uncordon the master

```bash
kubectl uncordon kubemaster
```

### Upgrade worker node

```text
# vagrant ssh kubemaster

$ kubectl get nodes
NAME         STATUS   ROLES                  AGE   VERSION
kubemaster   Ready    control-plane,master   43m   v1.20.10
kubenode01   Ready    <none>                 43m   v1.19.0
```

Drain the worker node:

```bash
kubectl drain kubenode01 --ignore-daemonsets
```

The worker node is drained:

```bash
$ kubectl get nodes
NAME         STATUS                     ROLES                  AGE   VERSION
kubemaster   Ready                      control-plane,master   48m   v1.20.10
kubenode01   Ready,SchedulingDisabled   <none>                 47m   v1.19.0
```

Upgrade k8s cluster components:

```bash
# vagrant ssh kubenode01

KUBE_VERSION=1.20.10
sudo apt-get install -y --allow-change-held-packages kubeadm=${KUBE_VERSION}-00

sudo kubeadm upgrade node

sudo apt-get install -y --allow-change-held-packages kubelet=${KUBE_VERSION}-00 kubectl=${KUBE_VERSION}-00
```

Check the nodes:

```text
$ kubectl uncordon kubenode01
node/kubenode01 uncordoned

$ kubectl get nodes
NAME         STATUS                     ROLES                  AGE   VERSION
kubemaster   Ready                      control-plane,master   53m   v1.20.10
kubenode01   Ready,SchedulingDisabled   <none>                 52m   v1.20.10
```

## Kubernetes Secrets

[Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

### Create pod with secrets

Create secrets:

```bash
kubectl create secret generic secret1 --from-literal username=admin1 --from-literal password=admin123
kubectl create secret generic secret2 --from-literal username=admin2 --from-literal password=admin321
```

Create pod which will use the secrets:

```bash
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: mypod
    image: nginx
    env:
      - name: USERNAME
        valueFrom:
          secretKeyRef:
            name: secret2
            key: username
      - name: PASSWORD
        valueFrom:
          secretKeyRef:
            name: secret2
            key: password
    volumeMounts:
    - name: secret1
      mountPath: "/secret1"
      readOnly: true
  volumes:
  - name: secret1
    secret:
      secretName: secret1
EOF
```

Check the secrets inside the containers:

```text
$ kubectl exec -it mypod -- bash -xc 'ls /secret1 ; echo $(cat /secret1/username); echo $(cat /secret1/password)'
+ ls /secret1
password  username
++ cat /secret1/username
+ echo admin1
admin1
++ cat /secret1/password
+ echo admin123
admin123

$ kubectl exec -it mypod -- env | grep -E '(USERNAME|PASSWORD)'
USERNAME=admin2
PASSWORD=admin321
```

### Access secrets "non-k8s" way

```text
# vagrant ssh kubenode01

$ sudo crictl ps
...
CONTAINER ID        IMAGE               CREATED             STATE               NAME                ATTEMPT             POD ID
879e08f431dd5       f8f4ffc8092c9       35 seconds ago      Running             mypod               0                   57c9f78887129
...
```

Check the container details where you can see the unencrypted environment
variables:

```text
$ sudo crictl inspect 879e08f431dd5
...
    "runtimeSpec": {
      "ociVersion": "1.0.2-dev",
      "process": {
        "user": {
          "uid": 0,
          "gid": 0
        },
        "args": [
          "/docker-entrypoint.sh",
          "nginx",
          "-g",
          "daemon off;"
        ],
        "env": [
...
          "USERNAME=admin2",
          "PASSWORD=admin321",
...
```

Let's check the values which are being mounted using the volumes:

```text
$ sudo crictl inspect 879e08f431dd5 | jq '.info.pid'
8661

$ sudo ls -l /proc/8661/root/secret1
total 0
lrwxrwxrwx 1 root root 15 Oct 11 11:02 password -> ..data/password
lrwxrwxrwx 1 root root 15 Oct 11 11:02 username -> ..data/username
```

### ETCD

Find ETCD details

```text
# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
```

```text
# ETCDCTL_API=3 etcdctl endpoint health \
  --cert=/etc/kubernetes/pki/apiserver-etcd-client.crt \
  --key=/etc/kubernetes/pki/apiserver-etcd-client.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt
127.0.0.1:2379 is healthy: successfully committed proposal: took = 876.099µs
```

```text
ETCDCTL_API=3 etcdctl get /registry/secrets/default/secret2 \
  --cert=/etc/kubernetes/pki/apiserver-etcd-client.crt \
  --key=/etc/kubernetes/pki/apiserver-etcd-client.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt
...
?{"f:data":{".":{},"f:password":{},"f:username":{}},"f:type":{}}
passworadmin321
usernameadmin2Opaque"
...
```

### Encrypt secrets in ETCD

Create `EncryptionConfiguration` for API server:

```bash
mkdir /etc/kubernetes/etcd
cat > /etc/kubernetes/etcd/encryptionconfiguration.yaml << EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: c2VjcmV0IGlzIHNlY3VyZQ==
    - identity: {}
EOF
```

Change API server to use the encryption:

```text
# vi /etc/kubernetes/manifests/kube-apiserver.yaml
...
spec:
  containers:
  - command:
    - kube-apiserver
    - --encryption-provider-config=/etc/kubernetes/etcd/encryptionconfiguration.yaml
...
    volumeMounts:
    - mountPath: /etc/kubernetes/etcd
      name: etcd
      readOnly: true
...
  volumes:
  - hostPath:
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate
    name: etcd
```

Create test secret which should be encrypted in ETCD:

```bash
kubectl create secret generic secret3 --from-literal username=admin3 --from-literal password=admin567
```

Read the secret from ETCD - it should be encrypted:

```text
ETCDCTL_API=3 etcdctl get /registry/secrets/default/secret3 \
  --cert=/etc/kubernetes/pki/apiserver-etcd-client.crt \
  --key=/etc/kubernetes/pki/apiserver-etcd-client.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  | hexdump -C
00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
00000010  73 2f 64 65 66 61 75 6c  74 2f 73 65 63 72 65 74  |s/default/secret|
00000020  33 0a 6b 38 73 3a 65 6e  63 3a 61 65 73 63 62 63  |3.k8s:enc:aescbc|
00000030  3a 76 31 3a 6b 65 79 31  3a f6 a9 70 c6 88 73 ef  |:v1:key1:..p..s.|
00000040  94 ca 74 d9 7e 8e 98 88  e0 ad 82 0a 44 67 72 17  |..t.~.......Dgr.|
00000050  6b 19 0d 62 f7 9b ec ed  57 40 a6 8f c4 87 d6 9c  |k..b....W@......|
...
```

## Container Runtime

[Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/)

Create `RuntimeClass` for gvisor:

```bash
kubectl apply -f - << EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

Crate pod

```bash
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: gvisor
  name: gvisor
spec:
  runtimeClassName: gvisor
  containers:
  - image: gvisor
    name: nginx
EOF
```

## Container security

[Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Security Context

```bash
kubectl run busybox --image=busybox --command --dry-run=client -o yaml -- sh -c 'sleep 1d'
```

Create busybox pod:

```bash
kubectl run busybox --image=busybox --command --dry-run=client -o yaml -- sh -c 'sleep 1d'
```

```bash
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: busybox
  name: busybox
spec:
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: busybox
    name: busybox
  restartPolicy: Never
EOF
```

The pod is running as "root":

```text
$ kubectl exec -it busybox -- sh -c 'set -x ; id ; touch /test123 ; ls -l /test123'
+ id
uid=0(root) gid=0(root) groups=10(wheel)
+ touch /test123
+ ls -l /test123
-rw-r--r--    1 root     root             0 Oct 12 05:20 /test123
```

Add `SecurityContext` to the pod definition:

```bash
kubectl apply --force=true --grace-period=1 -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: busybox
  name: busybox
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: busybox
    name: busybox
  restartPolicy: Never
EOF
```

Check permissions:

```text
$ kubectl exec -it busybox -- sh -c 'set -x ; id ; touch /tmp/test123 ; ls -l /tmp/test123'
+ id
uid=1000 gid=3000 groups=2000
+ touch /tmp/test123
+ ls -l /tmp/test123
-rw-r--r--    1 1000     3000             0 Oct 12 05:19 /tmp/test123
```

### Priviledged containers and PrivilegeEscalations

[Privileged](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged)

Container "root" user is mapped to the host "root" user.

```bash
kubectl apply --force=true --grace-period=1 -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: busybox
  name: busybox
spec:
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: busybox
    name: busybox
    securityContext:
      privileged: true
  restartPolicy: Never
EOF
```

Check permissions:

```text
$ kubectl exec -it busybox -- sh -c 'set -x ; sysctl kernel.hostname=attacker'
+ sysctl 'kernel.hostname=attacker'
kernel.hostname = attacker
```

### Pod Security Policy

[Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

PodSecurityPolicy is deprecated ([PodSecurityPolicy Deprecation: Past, Present, and Future](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/))
and your should use [Kyverno](https://github.com/kyverno/kyverno/) or [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper/)
instead.

[Create a policy and a pod](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#create-a-policy-and-a-pod)

Create new namespace and pod which stores the date in `/tmp/date` on the host:

```bash
kubectl create namespace my-namespace
kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: my-busybox
  name: my-busybox
  namespace: my-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-busybox
  template:
    metadata:
      labels:
        app: my-busybox
    spec:
      containers:
      - command: ["sh", "-c", "while true ; do date | tee /tmp/date ; sleep 5 ; done" ]
        image: busybox
        name: busybox
        volumeMounts:
        - mountPath: /tmp
          name: test-volume
      volumes:
      - name: test-volume
        hostPath:
          path: /tmp
EOF

kubectl exec -it -n my-namespace "$(kubectl get pod -n my-namespace -l app=my-busybox --no-headers -o custom-columns=':metadata.name')" -- cat /tmp/date
```

Enable admission Plugin PodSecurityPolicy in the API server:

```text
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
...
- --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
...
```

Create psp which doesn't allow `allowPrivilegeEscalation` or `privileged` and
allows usage of `HostPaths` for `/var/tmp` only:

```bash
kubectl apply -f - << EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: default
spec:
  privileged: false
  allowPrivilegeEscalation: false
  allowedHostPaths:
  - pathPrefix: /var/tmp
  allowedCapabilities:
  - NET_ADMIN
  - IPC_LOCK
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
EOF
```

Create `Role` and `RoleBinding` which allows to use "podsecuritypolicies":

```bash
kubectl create clusterrole psp-access --verb=use --resource=podsecuritypolicies
kubectl create clusterrolebinding psp-access --clusterrole=psp-access --group=system:serviceaccounts:my-namespace --namespace=my-namespace
```

All pods in `my-namespace` are allowed to use `HostPaths` in `/var/tmp/`.
If I restart the pod I got:

```text
$ kubectl delete pod -n my-namespace --all
$ kubectl describe replicasets.apps -n my-namespace
...
Events:
  Type     Reason            Age                    From                   Message
  ----     ------            ----                   ----                   -------
  Normal   SuccessfulCreate  13m                    replicaset-controller  Created pod: my-busybox-7d5b7688f9-wh655
  Warning  FailedCreate      4m5s (x17 over 4m46s)  replicaset-controller  Error creating: pods "my-busybox-7d5b7688f9-" is forbidden: PodSecurityPolicy: unable to admit pod: [spec.volumes[0].hostPath.pathPrefix: Invalid value: "/tmp": is not allowed to be used]
```

It's necessary to change the deployment to use `/var/tmp/` instead of `/tmp/`:

```bash
kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: my-busybox
  name: my-busybox
  namespace: my-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-busybox
  template:
    metadata:
      labels:
        app: my-busybox
    spec:
      containers:
      - command: ["sh", "-c", "while true ; do date | tee /tmp/date ; sleep 5 ; done" ]
        image: busybox
        name: busybox
        volumeMounts:
        - mountPath: /tmp
          name: test-volume
      volumes:
      - name: test-volume
        hostPath:
          path: /tmp
EOF
```

## Open Policy Agent (OPA)

[OPA Gatekeeper: Policy and Governance for Kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)

Install Gatekeeper:

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.5/deploy/gatekeeper.yaml
```

Check the CRDs:

```text
$ kubectl get crd | grep gatekeeper
configs.config.gatekeeper.sh                         2021-10-12T10:23:31Z
constraintpodstatuses.status.gatekeeper.sh           2021-10-12T10:23:31Z
constrainttemplatepodstatuses.status.gatekeeper.sh   2021-10-12T10:23:31Z
constrainttemplates.templates.gatekeeper.sh          2021-10-12T10:23:31Z
k8strustedimages.constraints.gatekeeper.sh           2021-10-12T10:41:26Z
```

Block pod to get image from `k8s.gcr.io` container registry.

Create `ConstraintTemplate`:

```bash
kubectl apply -f - << EOF
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8strustedimages
spec:
  crd:
    spec:
      names:
        kind: K8sTrustedImages
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8strustedimages
        violation[{"msg": msg}] {
          image := input.review.object.spec.containers[_].image
          startswith(image, "k8s.gcr.io/")
          msg := "Using images from k8s.gcr.io is not allowed !"
        }
EOF
```

Create `K8sTrustedImages` constraint

```bash
kubectl apply -f - << EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sTrustedImages
metadata:
  name: pod-trusted-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
EOF
```

Try it:

```text
$ kubectl run pause --image=k8s.gcr.io/pause:3.1
Error from server ([pod-trusted-images] Using images from k8s.gcr.io is not allowed !): admission webhook "validation.gatekeeper.sh" denied the request: [pod-trusted-images] Using images from k8s.gcr.io is not allowed !
```

```text
$ kubectl describe K8sTrustedImages pod-trusted-images
Name:         pod-trusted-images
...
Status:
  Audit Timestamp:  2021-10-12T10:56:48Z
  By Pod:
    Constraint UID:       39aaf68c-2921-42ec-977e-0c63f6623764
    Enforced:             true
    Id:                   gatekeeper-audit-6c558d7455-fv8c5
    Observed Generation:  1
    Operations:
      audit
      status
    Constraint UID:       39aaf68c-2921-42ec-977e-0c63f6623764
    Enforced:             true
    Id:                   gatekeeper-controller-manager-ff8849b64-nh65b
    Observed Generation:  1
...
  Total Violations:  8
  Violations:
    Enforcement Action:  deny
    Kind:                Pod
    Message:             Using images from k8s.gcr.io is not allowed !
    Name:                coredns-558bd4d5db-k6qfn
    Namespace:           kube-system
    Enforcement Action:  deny
    Kind:                Pod
    Message:             Using images from k8s.gcr.io is not allowed !
    Name:                coredns-558bd4d5db-q9mzm
    Namespace:           kube-system
    Enforcement Action:  deny
    Kind:                Pod
    Message:             Using images from k8s.gcr.io is not allowed !
    Name:                etcd-kubemaster
    Namespace:           kube-system
...
Events:                  <none>
```

Delete all "Constraints" and "ConstraintTemplates":

```bash
kubectl delete K8sTrustedImages,ConstraintTemplates --all
```
