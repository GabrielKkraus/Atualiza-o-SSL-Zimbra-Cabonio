#!/bin/bash

# ========== LOG ==========
log_file="/var/log/renew_zextras_cert.log"
exec > >(tee -a "$log_file") 2>&1
echo "===== Início do processo: $(date) ====="

# ========== CONFIGURAÇÕES ==========
certs_dom=$(hostname -f 2>/dev/null)
[ -z "$certs_dom" ] && certs_dom=$(hostname)
cert_path="/root/.acme.sh/$certs_dom"
tmp_path="lets"
tmp_dir="/tmp/$tmp_path.$certs_dom"
email="infra@serverdo.in"
zerossl="no"
letsencrypt="yes"

# ========== OBTÉM IP PÚBLICO ==========
meu_ip=$(curl -s https://api.ipify.org)
if [ -z "$meu_ip" ]; then
    echo "[ERRO] Não foi possível obter o IP público"
    exit 1
fi

# ========== OBTÉM DOMÍNIOS DO ZEXTRAS ==========
if ! id zextras &>/dev/null; then
    echo "[ERRO] Usuário zextras não existe. Este script é destinado a servidores com Zextras."
    exit 1
fi

echo "[INFO] Buscando domínios no Zextras..."
dominios=$(su - zextras -c "/opt/zextras/bin/zmprov gad" 2>/dev/null)

# ========== GERA dom_list COM DOMÍNIOS QUE APONTAM PARA ESTE SERVIDOR ==========
dom_list=""
for dominio in $dominios; do
  for sub in "" "mail." "webmail."; do
    fqdn="${sub}${dominio}"
    ip_resolvido=$(dig +short A "$fqdn" | head -n1)
    if [ "$ip_resolvido" = "$meu_ip" ]; then
      dom_list+=" -d $fqdn"
      echo "[VALIDADO] $fqdn → $ip_resolvido"
    else
      echo "[IGNORADO] $fqdn → $ip_resolvido (não aponta para $meu_ip)"
    fi
  done
done

if [ -z "$dom_list" ]; then
    echo "[ERRO] Nenhum domínio válido apontando para este servidor foi encontrado."
    exit 1
fi

# ========== PARANDO SERVIÇOS ==========
echo "[INFO] Parando o Nginx..."
systemctl stop nginx

echo "[INFO] Parando o Zextras..."
su - zextras -c "zmcontrol stop"

# ========== INSTALAÇÃO DO ACME.SH E DEPENDÊNCIAS ==========
apt -y install socat dnsutils curl wget

if [ ! -d "/root/.acme.sh" ]; then
    echo "[INFO] Instalando acme.sh..."
    curl https://get.acme.sh | sh
fi

cd /root/.acme.sh || { echo "[ERRO] Não foi possível acessar o diretório do acme.sh"; exit 1; }

[ -d "$cert_path" ] && rm -rf "$cert_path"

# ========== EMISSÃO DO CERTIFICADO ==========
./acme.sh --set-default-ca --server letsencrypt_test
./acme.sh --issue --standalone --force --preferred-chain "ISRG Root X1" --keylength 2048 $dom_list || {
    echo "[ERRO] Falha na emissão com Let's Encrypt (teste)"
    exit 1
}

[ -d "$cert_path" ] && rm -rf "$cert_path"

./acme.sh --set-default-ca --server letsencrypt
./acme.sh --issue --standalone --force --preferred-chain "ISRG Root X1" --keylength 2048 $dom_list || {
    echo "[ERRO] Falha na emissão com Let's Encrypt (produção)"
    exit 1
}

# ========== CONFIGURAÇÃO DO CERTIFICADO ==========
cd "$cert_path" || exit 1
mkdir -p "$tmp_dir"
rm -rf "$tmp_dir"/*
cp * "$tmp_dir"
cd "$tmp_dir" || exit 1
wget --no-check-certificate -O ISRG-X1.pem https://letsencrypt.org/certs/isrgrootx1.pem
cat fullchain.cer ISRG-X1.pem > zextras_ca.pem

# ========== DEPLOY NO ZEXTRAS ==========
chown zextras: "$tmp_dir" -R

su - zextras -c "cd $tmp_dir && /opt/zextras/bin/zmcertmgr verifycrt comm $certs_dom.key $certs_dom.cer zextras_ca.pem" || {
    echo "[ERRO] Verificação do certificado falhou"
    exit 1
}

cp "$certs_dom.key" /opt/zextras/ssl/zimbra/commercial/commercial.key -rf
chown zextras: /opt/zextras/ssl/zimbra/commercial/commercial.key

su - zextras -c "cd $tmp_dir && /opt/zextras/bin/zmcertmgr deploycrt comm $certs_dom.cer zextras_ca.pem"

# ========== REINÍCIO ==========
echo "[INFO] Iniciando o Zextras..."
su - zextras -c "zmcontrol start"

echo "[INFO] Reiniciando o Nginx..."
systemctl start nginx

echo "===== Certificado renovado com sucesso para $certs_dom - $(date) ====="

