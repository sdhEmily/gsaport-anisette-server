# gsaport-anisette-server

A fork of anisette-v3-server for GSAPort

## Run using Docker

```bash
docker run -d --restart always --name gsaport-anisette -p 6969:6969 --volume gsaport-anisette_data:/home/Alcoholic/.config/gsaport-anisette/lib/ dadoum/gsaport-anisette-server
```

## Compile using dub

```bash
apt update && apt install --no-install-recommends -y ca-certificates ldc git clang dub libz-dev libssl-dev
git clone https://github.com/sdhEmily/gsaport-anisette-server.git; cd gsaport-anisette-server
DC=ldc2 dub build -c "static" --build-mode allAtOnce -b release --compiler=ldc2
stat gsaport-anisette-server
```

## Ansible

If you want to quickly setup gsaport-anisette with ansible, just use the setup-gsaport-anisette-ansible.yaml playbook.
Setup your inventory and choose your desired host in the playbook. Tweak your parameters/ansible.cfg for the remote_user you use. Requires root.
```bash
ansible-playbook -i inventory setup-gsaport-anisette-ansible.yaml -k
```