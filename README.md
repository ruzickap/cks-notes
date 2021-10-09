# CKS Notes

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

sudo apt-get install -y apt-transport-https ca-certificates curl lsb-release mc tree

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
