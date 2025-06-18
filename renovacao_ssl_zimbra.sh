#!/bin/bash

# ========== LOG ==========
log_file="/var/log/renew_zimbra_cert.log"
exec > >(tee -a "$log_file") 2>&1
echo "===== Início do processo: $(date) ====="

# ========== CONFIGURAÇÕES ==========
certs_dom=$(hostname -f 2>/dev/null)
[ -z "$certs_dom" ] && certs_dom=$(hostname)
cert_path="/root/.acme.sh/$certs_dom"
zerossl="no"
letsencrypt="yes"
email="infra@serverdo.in"

# ========== OBTÉM IP PÚBLICO ==========
meu_ip=$(curl -s https://api.ipify.org)
if [ -z "$meu_ip" ]; then
    echo "[ERRO] Não foi possível obter o IP público"
    exit 1
fi

# ========== OBTÉM DOMÍNIOS DO ZIMBRA ==========
if ! id zimbra &>/dev/null; then
    echo "[ERRO] Usuário zimbra não existe. Este script é destinado a servidores com Zimbra."
    exit 1
fi

echo "Buscando domínios no Zimbra..."
dominios=$(su - zimbra -c "zmprov gad" 2>/dev/null)

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
echo "Parando o Nginx..."
killall nginx

echo "Parando o Zimbra..."
su - zimbra -c "zmcontrol stop"

# ========== AJUSTANDO /etc/resolv.conf ==========
echo "nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 127.0.0.1" > /etc/resolv.conf
echo "[INFO] /etc/resolv.conf ajustado"

# ========== INSTALAÇÃO DO ACME.SH ==========
apt -y install socat dnsutils curl wget

if [ ! -d "/root/.acme.sh" ]; then
    echo "Instalando acme.sh..."
    curl https://get.acme.sh | sh
fi

cd /root/.acme.sh || { echo "[ERRO] Não foi possível acessar o diretório do acme.sh"; exit 1; }
[ -d "$cert_path" ] && rm -rf "$cert_path"

# ========== GERAÇÃO DO CERTIFICADO ==========
if [ "$zerossl" = "yes" ] && [ "$letsencrypt" = "yes" ]; then
    echo "[ERRO] Não é possível usar zerossl e letsencrypt ao mesmo tempo."
    exit 1
fi

if [ "$zerossl" = "no" ] && [ "$letsencrypt" = "no" ]; then
    echo "[ERRO] Defina zerossl ou letsencrypt como 'yes'."
    exit 1
fi

if [ "$zerossl" = "yes" ]; then
    ./acme.sh --register-account -m "$email"
    ./acme.sh --issue --standalone --keylength 2048 $dom_list || {
        echo "[ERRO] Falha na emissão com ZeroSSL"
        exit 1
    }
fi

if [ "$letsencrypt" = "yes" ]; then
    ./acme.sh --set-default-ca --server letsencrypt
    ./acme.sh --issue --standalone --preferred-chain "ISRG Root X1" --keylength 2048 $dom_list || {
        echo "[ERRO] Falha na emissão com Let's Encrypt"
        exit 1
    }
fi

# ========== CONFIGURAÇÃO DO CERTIFICADO ==========
cd "$cert_path" || exit 1
tmp_path=""

if [ "$letsencrypt" = "yes" ]; then
    tmp_path="lets"
    mkdir -p "/tmp/$tmp_path.$certs_dom"
    rm -rf "/tmp/$tmp_path.$certs_dom"/*
    cp * "/tmp/$tmp_path.$certs_dom"
    cd "/tmp/$tmp_path.$certs_dom" || exit 1

    # Corrigido: baixar CA correta do Let's Encrypt
    wget --no-check-certificate -O ISRG-X1.pem https://letsencrypt.org/certs/isrgrootx1.pem
    cat fullchain.cer ISRG-X1.pem > zimbra_ca.pem
fi

if [ "$zerossl" = "yes" ]; then
    tmp_path="zero"
    mkdir -p "/tmp/$tmp_path.$certs_dom"
    rm -rf "/tmp/$tmp_path.$certs_dom"/*
    cp * "/tmp/$tmp_path.$certs_dom"
    cd "/tmp/$tmp_path.$certs_dom" || exit 1

    wget --no-check-certificate -O USERTrust.crt http://www.tbs-x509.com/USERTrustRSACertificationAuthority.crt
    cat fullchain.cer USERTrust.crt > zimbra_ca.pem
fi

# ========== DEPLOY NO ZIMBRA ==========
chown zimbra: "/tmp/$tmp_path.$certs_dom" -R

su - zimbra -c "cd /tmp/$tmp_path.$certs_dom && /opt/zimbra/bin/zmcertmgr verifycrt comm $certs_dom.key $certs_dom.cer zimbra_ca.pem" || {
    echo "[ERRO] Verificação do certificado falhou"
    exit 1
}

cp "$certs_dom.key" /opt/zimbra/ssl/zimbra/commercial/commercial.key -rf
chown zimbra: /opt/zimbra/ssl/zimbra/commercial/commercial.key

su - zimbra -c "cd /tmp/$tmp_path.$certs_dom && /opt/zimbra/bin/zmcertmgr deploycrt comm $certs_dom.cer zimbra_ca.pem"

# ========== REINÍCIO ==========
echo "Iniciando o Zimbra..."
su - zimbra -c "zmcontrol start"

echo "===== Certificado renovado com sucesso para $certs_dom - $(date) ====="