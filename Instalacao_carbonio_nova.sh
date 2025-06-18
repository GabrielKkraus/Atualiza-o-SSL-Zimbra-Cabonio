#!/bin/bash 

# Ricardo - ServerDo.in - 2024-09-21 - Pedido do Guilherme José Salles Gerente Infra que esse script só possa ser executado após rodar o scriptbase/instalacao_base.sh
# Caminho do arquivo de configuração do SSH
SSH_CONFIG="/etc/ssh/sshd_config"

# Verificar se o arquivo existe
if [ ! -f "$SSH_CONFIG" ]; then
    echo "Arquivo de configuração SSH não encontrado: $SSH_CONFIG"
    exit 1
fi

# Procurar pela linha que define a porta no arquivo de configuração
PORTA_CONFIGURADA=$(grep "^Port " $SSH_CONFIG | awk '{print $2}')

# Verificar se a porta está configurada como 51439
if [ "$PORTA_CONFIGURADA" != "51439" ]; then
    echo "Parece que você não rodou o scriptbase/instalacao_base.sh"
    exit 1
fi


# Based on the origian work published on Carbonio's Official docs available at
# https://docs.zextras.com/carbonio-ce/html/install/scenarios/single-server-scenario.html

# modified by
# Anahuac Gil (anahuac@kyasolutions.com.br) 2024-03
# Mateus Batista AKA madruga (madruga@gnu.works) 2024-04

version=v9

# Define ANSI color codes for colored output
RED='\033[0;31m'	# Failed - Red
GREEN='\033[0;32m'	# Done - Green
YELLOW='\033[0;33m'	# Pending - Yellow
LIGHT_GRAY='\033[0;37m'	# Next - Light Gray (off-white)
NC='\033[0m'		# No Color - Reset

#PRE-INSTALL STEPS

apt update && apt upgrade -y
apt purge -y ssmtp
source /etc/os-release

# Hostname
c_hostname=$(hostname)
hostnamectl set-hostname $c_hostname

# Hostname
c_domain=$(hostname)

# IP address and /etc/hosts
c_address=$(hostname -I)
echo "127.0.0.1 localhost" > /etc/hosts
echo "$c_address $(hostname -f) $(hostname -s)" >> /etc/hosts

# Gerar uma senha aleatória de 10 caracteres (letras maiúsculas, minúsculas e números)
c_consul_password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c10)
c_postgres_password=$c_consul_password
c_admin_password=$c_consul_password

# Salvar a senha no arquivo /root/.carbonio
echo "$c_consul_password" > /root/.carbonio
chmod 600 /root/.carbonio

# Informar o usuário sobre a senha gerada
echo "As senhas para Consul, PostgreSQL e Carbonio Admin foram geradas."
echo "A senha gerada é: $c_consul_password"
echo "Ela foi salva no arquivo /root/.carbonio para consulta futura."
echo "Por favor, copie a senha e pressione qualquer tecla para continuar."

# Aguardar o usuário pressionar qualquer tecla para continuar
read -n 1 -s -r -p "Pressione qualquer tecla para continuar"

echo "Continuando o script..."

# systemd-resolved
sed -i s/"#DNS="/"DNS=8.8.8.8"/g /etc/systemd/resolved.conf

# IPV6
echo "Disabling IPV6..."
ipv6_test=$(grep net.ipv6.conf.all.disable_ipv6 /etc/sysctl.conf)
if [ -z "$ipv6_test" ] ; then
	echo "" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p > /dev/null
fi
if [ ! -f /etc/rc.local ] ; then 
	>/etc/rc.local
	echo "#! /bin/bash" >> /etc/rc.local
	chmod +x /etc/rc.local
fi
echo "sysctl -p" >> /etc/rc.local

apt install -y binutils

HOST=$c_hostname;
DOMAIN=$c_domain;
IP=$c_address;
virus_account=$(echo "virus-quarantine.$(strings /dev/urandom | tr -dc _A-Z-a-z-0-9 | head -c10)@$c_domain")
spam_account=$(echo "spam.$(strings /dev/urandom | tr -dc _A-Z-a-z-0-9 | head -c10)@$c_domain")
ham_account=$(echo "ham.$(strings /dev/urandom | tr -dc _A-Z-a-z-0-9 | head -c10)@$c_domain")


printf "Carbonio will be installed on $YELLOW${HOST}$NC, using $YELLOW${DOMAIN}$NC as default domain and $YELLOW${IP}$NC as public IP\n"
read -p "Ready to go? (press Enter to continue...)" c_continue

# Repository
wget -c  https://repo.zextras.io/inst_repo_ubuntu.sh && bash inst_repo_ubuntu.sh
echo "Public Zextras repository added for Ubuntu 22.04LTS (Jammy)..."

apt update -y

#INSTALL STEPS

package_name="carbonio-core"

if apt-cache search "$package_name" | grep -q "$package_name"; then
    echo "Start Carbonio installation"
#echo "deb http://apt.postgresql.org/pub/repos/apt focal-pgdg main" > /etc/apt/sources.list.d/pgdg.list;
#wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add - ;

sh -c 'echo "deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'

wget -O- "https://www.postgresql.org/media/keys/ACCC4CF8.asc" | gpg --dearmor | sudo tee /usr/share/keyrings/postgres.gpg > /dev/null
chmod 644 /usr/share/keyrings/postgres.gpg
sed -i 's/deb/deb [signed-by=\/usr\/share\/keyrings\/postgres.gpg] /' /etc/apt/sources.list.d/pgdg.list

PACKAGES="postgresql-16 service-discover-server carbonio-directory-server carbonio-proxy carbonio-webui carbonio-files-ui carbonio-mta carbonio-mailbox-db carbonio-appserver carbonio-user-management carbonio-files-ce carbonio-files-public-folder-ui carbonio-files-db carbonio-tasks-ce carbonio-tasks-db carbonio-tasks-ui carbonio-storages-ce carbonio-preview-ce carbonio-docs-connector-ce carbonio-docs-connector-db carbonio-docs-editor carbonio-prometheus carbonio-message-broker  carbonio-ws-collaboration-ce carbonio-ws-collaboration-db carbonio-ws-collaboration-ui"

echo "
HOSTNAME="$c_hostname"
AVDOMAIN="$c_domain"
AVUSER="zextras@$c_domain"
CREATEADMIN="zextras@$c_domain"
CREATEDOMAIN="$c_domain"
DOCREATEADMIN="yes"
DOCREATEDOMAIN="yes"
LDAPHOST="$c_hostname"
SMTPDEST="zextras@$c_domain"
SMTPHOST="$c_hostname"
SMTPSOURCE="zextras@$c_domain"
SNMPTRAPHOST="$c_hostname"
SPELLURL="http://$c_hostname:7780/aspell.php"
VIRUSQUARANTINE="$virus_account"
TRAINSAHAM="$spam_account"
TRAINSASPAM="$ham_account"
zimbraDefaultDomainName="$c_domain"
zimbraVersionCheckNotificationEmail="zextras@$c_domain"
zimbraVersionCheckNotificationEmailFrom="zextras@$c_domain"
zimbra_server_hostname="$c_hostname"
" > config.conf
apt update -y -q
apt upgrade -y -q
apt install -y $PACKAGES 

carbonio-bootstrap -c ./config.conf

CONSUL_SECRET="$c_consul_password"
POSTGRES_SECRET="$c_postgres_password"

service-discover setup $c_address --password=$CONSUL_SECRET 

export CONSUL_HTTP_TOKEN=$(echo $CONSUL_SECRET | gpg --batch --yes --passphrase-fd 0 -qdo - /etc/zextras/service-discover/cluster-credentials.tar.gpg | tar xOf - consul-acl-secret.json | jq .SecretID -r);
export SETUP_CONSUL_TOKEN=$CONSUL_HTTP_TOKEN

pending-setups --execute-all

su - postgres -c "psql --command=\"CREATE ROLE carbonio_adm WITH LOGIN SUPERUSER encrypted password '$POSTGRES_SECRET';\""
su - postgres -c "psql --command=\"CREATE DATABASE carbonio_adm OWNER carbonio_adm;\""

PGPASSWORD=$POSTGRES_SECRET carbonio-files-db-bootstrap carbonio_adm 127.0.0.1
PGPASSWORD=$POSTGRES_SECRET carbonio-mailbox-db-bootstrap carbonio_adm 127.0.0.1
PGPASSWORD=$POSTGRES_SECRET carbonio-docs-connector-db-bootstrap carbonio_adm 127.0.0.1
PGPASSWORD=$POSTGRES_SECRET carbonio-tasks-db-bootstrap carbonio_adm 127.0.0.1
PGPASSWORD=$POSTGRES_SECRET carbonio-ws-collaboration-db-bootstrap carbonio_adm 127.0.0.1

PACKAGES="carbonio-message-dispatcher-db"
apt install -y $PACKAGES
pending-setups --execute-all
PGPASSWORD=$POSTGRES_SECRET carbonio-message-dispatcher-db-bootstrap carbonio_adm 127.0.0.1

PACKAGES="carbonio-message-dispatcher"
apt install -y $PACKAGES
pending-setups --execute-all
PGPASSWORD=$POSTGRES_SECRET carbonio-message-dispatcher-migration carbonio_adm 127.0.0.1

PACKAGES="carbonio-videoserver-ce"
DEBIAN_FRONTEND=noninteractive apt install -y $PACKAGES
sed -i '/nat_1_1_mapping/c\        nat_1_1_mapping = "'$c_address'"' /etc/janus/janus.jcfg
pending-setups --execute-all

sudo -iu zextras -- bash <<EOF
	carbonio prov mcf zimbraDefaultDomainName $DOMAIN
	carbonio prov md  $DOMAIN zimbraVirtualHostname $DOMAIN
	carbonio prov mc default carbonioFeatureChatsEnabled TRUE
	carbonio prov setpassword zextras@$DOMAIN $c_admin_password
EOF

systemctl restart carbonio-tasks && systemctl restart carbonio-ws-collaboration && systemctl restart carbonio-message-dispatcher && systemctl restart carbonio-videoserver && systemctl restart networkd-dispatcher.service

reset

#echo service discover and postgresql passwords
echo -e "The service-discover password is: \e[1m $CONSUL_SECRET \e[0m" 
echo -e "You can find it in file \e[3m/var/lib/service-discover/password\e[0m."
echo ""
echo -e "The PostgreSQL password (DB_ADM_PWD) is: \e[1m$POSTGRES_SECRET\e[0m"
echo "Please store it in a safe place, otherwise you will need to reset it!"
echo ""
echo -e "The zextras@$DOMAIN password is: \e[1m$c_admin_password\e[0m"
echo "Please store it in a safe place, otherwise you will need to reset it!"

else
    echo "###### Carbonio repo are not configured. ######"
fi

# Certificando que o NGINX externo ao Carbonio nao vai afetar o funcionamento
systemctl disable nginx

#### Configurando IPTABLES
echo "Configurando IPTABLES"
# Define o novo IPTABLES
novo_iptables=$(cat <<EOL
*filter
:INPUT ACCEPT [0:102354]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [92952:20764374]

##Liberando para todos os IPs da ServerDo.in
-A INPUT -i eth0 -s 190.89.238.0/23 -j ACCEPT
-A INPUT -i eth0 -s 18.229.26.112 -j ACCEPT
-A INPUT -i eth0 -s 199.119.103.235 -j ACCEPT
-A INPUT -i eth0 -s 162.243.24.125 -j ACCEPT

##Liberando para os IPs do CloudFlare
-A INPUT -i eth0 -s 103.21.244.0/22 -j ACCEPT
-A INPUT -i eth0 -s 103.22.200.0/22 -j ACCEPT
-A INPUT -i eth0 -s 103.31.4.0/22 -j ACCEPT
-A INPUT -i eth0 -s 104.16.0.0/13 -j ACCEPT
-A INPUT -i eth0 -s 104.24.0.0/14 -j ACCEPT
-A INPUT -i eth0 -s 108.162.192.0/18 -j ACCEPT
-A INPUT -i eth0 -s 131.0.72.0/22 -j ACCEPT
-A INPUT -i eth0 -s 141.101.64.0/18 -j ACCEPT
-A INPUT -i eth0 -s 162.158.0.0/15 -j ACCEPT
-A INPUT -i eth0 -s 172.64.0.0/13 -j ACCEPT
-A INPUT -i eth0 -s 173.245.48.0/20 -j ACCEPT
-A INPUT -i eth0 -s 188.114.96.0/20 -j ACCEPT
-A INPUT -i eth0 -s 190.93.240.0/20 -j ACCEPT
-A INPUT -i eth0 -s 197.234.240.0/22 -j ACCEPT
-A INPUT -i eth0 -s 198.41.128.0/17 -j ACCEPT

##Liberando para os IPs do UptimeRobots
-A INPUT -i eth0 -s 69.162.124.224/28 -j ACCEPT
-A INPUT -i eth0 -s 63.143.42.240/28 -j ACCEPT
-A INPUT -i eth0 -s 216.245.221.80/28 -j ACCEPT
-A INPUT -i eth0 -s 208.115.199.16/28 -j ACCEPT
-A INPUT -i eth0 -s 104.131.107.63 -j ACCEPT
-A INPUT -i eth0 -s 122.248.234.23 -j ACCEPT
-A INPUT -i eth0 -s 128.199.195.156 -j ACCEPT
-A INPUT -i eth0 -s 138.197.150.151 -j ACCEPT
-A INPUT -i eth0 -s 139.59.173.249 -j ACCEPT
-A INPUT -i eth0 -s 146.185.143.14 -j ACCEPT
-A INPUT -i eth0 -s 159.203.30.41 -j ACCEPT
-A INPUT -i eth0 -s 159.89.8.111 -j ACCEPT
-A INPUT -i eth0 -s 165.227.83.148 -j ACCEPT
-A INPUT -i eth0 -s 178.62.52.237 -j ACCEPT
-A INPUT -i eth0 -s 18.221.56.27 -j ACCEPT
-A INPUT -i eth0 -s 167.99.209.234 -j ACCEPT
-A INPUT -i eth0 -s 216.144.250.150 -j ACCEPT
-A INPUT -i eth0 -s 34.233.66.117 -j ACCEPT
-A INPUT -i eth0 -s 46.101.250.135 -j ACCEPT
-A INPUT -i eth0 -s 52.60.129.180 -j ACCEPT
-A INPUT -i eth0 -s 54.64.67.106 -j ACCEPT
-A INPUT -i eth0 -s 54.67.10.127 -j ACCEPT
-A INPUT -i eth0 -s 54.79.28.129 -j ACCEPT
-A INPUT -i eth0 -s 54.94.142.218 -j ACCEPT
-A INPUT -i eth0 -s 52.70.84.165 -j ACCEPT
-A INPUT -i eth0 -s 54.225.82.45 -j ACCEPT

## Incrementar o firewall contrar ataques
-A INPUT -i eth0 -m conntrack --ctstate INVALID -j DROP

## Liberando ssh, web, https, smtp, dns e snmp
-A INPUT -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i eth0 -p icmp -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 51439 -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 25 -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 53 -j ACCEPT
-A INPUT -i eth0 -p udp --dport 53 -j ACCEPT
-A INPUT -i eth0 -p udp --dport 161 -j ACCEPT
-A INPUT -i eth0 -p udp --dport 162 -j ACCEPT
## Regras utilizadas pelo Zimbra
-A INPUT -i eth0 -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 8443 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 110 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 143 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 465 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 587 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 993 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 995 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 6071 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 7782 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 389 -s localhost -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 7073 -s localhost -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 7025 -s localhost -j ACCEPT

## Ativando logs no kern.log
#-A INPUT -i eth0 -j LOG

# Se não estiver nas regras anteriores, negamos!!
-A INPUT -i eth0 -j DROP

COMMIT
EOL
)

# Verifica se o arquivo existe antes de substituí-lo
if [ -f "/etc/iptables/rules.v4" ]; then
    # Substitui o conteúdo do arquivo pelo novo texto
    echo -e "$novo_iptables" > "/etc/iptables/rules.v4"
    echo "Conteúdo de /etc/iptables/rules.v4 substituído com sucesso."
    sleep 2
    echo "Realizando Flush no Iptables"
    iptables -F; iptables-restore < /etc/iptables/rules.v4
else
    echo "O arquivo /etc/iptables/rules.v4 não foi encontrado."
fi

### Corrigindo a interface do Iptables
#Obter o primeiro nome de interface de rede sem o :
interface=$(ifconfig | awk '/^[a-zA-Z0-9]+/ {print $1}' | sed 's/:$//' | head -n 1)

# Verificar se a interface é ens3
if [ "$interface" = "ens3" ]; then
  echo "Interface ens3 encontrada. Atualizando /etc/iptables/rules.v4..."
  sed -i "s/eth0/ens3/g" /etc/iptables/rules.v4
  echo "Atualização concluída."
else
  echo "A interface encontrada não é ens3. Nenhuma alteração realizada."
fi

#### Configurando Porta e Usuário de Acesso
echo "Configurando Porta e Usuário de Acesso"
su - zextras -c "zmprov mcf zimbraRemoteManagementPort 51439"

#### Configurando cbpolicyd padrão
su - zextras -c "carbonio prov modifyserver $(hostname) +zimbraServiceEnabled cbpolicyd"
su - zextras -c "carbonio prov ms $(hostname) zimbraCBPolicydQuotasEnabled TRUE"
cp policy_members.sql quota_send.sql /opt/zextras/data/cbpolicyd/db/
su - zextras -c "sqlite3 /opt/zextras/data/cbpolicyd/db/cbpolicyd.sqlitedb < policy_members.sql"
su - zextras -c "sqlite3 /opt/zextras/data/cbpolicyd/db/cbpolicyd.sqlitedb < quota_send.sql"

#### Configurando crons
cp backup-zextras /opt/zextras/backup/
cp serverdoin-cron-zextras /etc/cron.d/

# Cria o arquivo carbonio.local em /etc/fail2ban/jail.d/
cat <<EOL > /etc/fail2ban/jail.d/carbonio.local
[DEFAULT]
# "ignoreip" can be an IP address, a CIDR mask or a DNS host. Fail2ban will not
# ban a host which matches an address in this list. Several addresses can be
# defined using space separator.
ignoreip = 127.0.0.1/8 ::1 190.89.238.0/23

# "bantime" is the number of seconds that a host is banned.
bantime = 600
# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime = 600

# "maxretry" is the number of failures before a host gets banned.
maxretry = 3
banaction = ufw

# Carbonio Jails.

[carbonio-account]
enabled = true
filter = carbonio
action = iptables-allports[name=carbonio-account]
#sendmail[name=carbonio-account, dest=zextras@domain.tld]
logpath = /opt/zextras/log/mailbox.log
bantime = 600
maxretry = 3

[carbonio-audit]
enabled = true
filter = carbonio
action = iptables-allports[name=carbonio-audit]
#sendmail[name=Carbonio-audit, dest=zextras@domain.tld]
logpath = /opt/zextras/log/audit.log
bantime = 600
maxretry = 3

[carbonio-recipient]
enabled = true
filter = carbonio
action = iptables-allports[name=carbonio-recipient]
#sendmail[name=Carbonio-recipient, dest=zextras@domain.tld]
logpath = /var/log/carbonio.log
bantime = 172800
maxretry = 3

[postfix]
enabled = true
filter = postfix
action = iptables-multiport[name=postfix, port=smtp, protocol=tcp]
#sendmail-buffered[name=Postfix, dest=zextras@domain.tld]
logpath = /var/log/carbonio.log
bantime = 172800
maxretry = 3
EOL

# Reinicia o serviço fail2ban
service fail2ban restart

echo "Arquivo carbonio.local criado e serviço fail2ban reiniciado."

## Instalacao necessaria para DKIM
apt-get install libxml-simple-perl -y

######## Instalacao do script para SSL
# Gerando o certificado Let's Encrypt com acme.sh

su - zextras -c "zmcontrol stop"
apt -y install socat
wget -O - https://get.acme.sh | sh

# Cria o diretório, se ele não existir
mkdir -p /opt/serverdoin/scripts

# Cria o arquivo atualiza_ssl_acme.sh com o conteúdo fornecido
cat << 'EOF' > /opt/serverdoin/scripts/atualiza_ssl_acme.sh
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

EOF

# Concede permissão de execução
chmod +x /opt/serverdoin/scripts/atualiza_ssl_acme.sh

# Ricardo ServerDo.in - 2024-09-23 - Tem que ativar o SSL, por isso vamos rodar o script que acabamos de criar
bash /opt/serverdoin/scripts/atualiza_ssl_acme.sh

#Start dos servicos do carbonio
su - zextras -c "zmcontrol start"

#su - zextras -c "zmprov ms `zmhostname` -zimbraServiceEnabled service-discover"

# Ricardo ServerDo.in - 2024-09-20 - Nova parte do script para ativar nossos scripts, cron de checagem e status.txt - testei script abaixo na us16 sem problemas
# Ricardo ServerDo.in - 2024-09-21 - Fiz testes e melhorias na us3 e us313 da parte abaixo

cat << 'EOF'  > /usr/local/bin/java-heap-incremental
#!/bin/bash
cat /opt/zextras/log/mailbox.log | grep "java.lang.OutOfMemoryError: Java heap space" > /opt/zextras/log/java_heap_out_of_memory.log
LOG="/opt/zextras/log/java_heap_out_of_memory.log"
OFFSET_FILE=/tmp/log-incremental.offset
if [ ! -f $OFFSET_FILE ]; then echo 0 > $OFFSET_FILE; fi
OFFSET=`cat $OFFSET_FILE`
FILESIZE=`cat $LOG|wc -c`
# Check if log has been rotated
if [ "$OFFSET" -gt "$FILESIZE" ]; then
  OFFSET=0
  echo 0 > $OFFSET_FILE
fi
if [ "$FILESIZE" -gt "$OFFSET" ]; then
  tail -c+$OFFSET $LOG|sed "s/^/  /"
  echo $FILESIZE > $OFFSET_FILE
fi
EOF

# Concede permissão de execução
chmod +x /usr/local/bin/java-heap-incremental

cat << 'EOF' > /opt/serverdoin/scripts/checkcarboniostatus.sh
#!/bin/bash
#executa zmcontrol status e manda para status.txt
date > /opt/zextras/mailboxd/webapps/zimbra/status.txt && su - zextras -c 'zmcontrol status' | grep -v logger | grep -v zmlogswatchctl | grep -v stats | grep -v snmp | grep -v zmswatch >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
# Validar erro do uptime by vinicius
datastatus=$(date +"%Y%m%d%H%M")
nomearquivo=$(echo "status_$datastatus.txt")
#verifica postfix
checkstatus1=`tail -n 500 /var/log/carbonio.log | grep "Mail system is down" | wc -l`
if [ $checkstatus1 -gt 0 ]
then
        echo $checkstatus1;
        echo "Mail system Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
        echo "Mail system Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/$nomearquivo
else
        echo "Mail system Running" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
fi
#verifica policyd
checkstatus2=`tail -n 500 /var/log/carbonio.log | grep "connect to localhost:10031: Connection refused" | wc -l`
if [ $checkstatus2 -gt 0 ]
then
        echo $checkstatus2;
        echo "Policyd Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
        echo "Policyd Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/$nomearquivo

else
    echo "Policyd Running" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt

fi
#verifica milter - Ricardo - ServerDo.in - 2024-09-17 - Trocamos o formato do grep por mudança de versão para o carbonio
checkstatus3=`tail -n 500 /var/log/carbonio.log | grep "dkimmilter.*451 4.7.1 Service unavailable" | wc -l`
if [ $checkstatus3 -gt 0 ]
then
        echo $checkstatus3;
        echo "Milter Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
        echo "Milter Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/$nomearquivo
else
    echo "Milter Running" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt

fi
# Verifica se o Java heap ficou sem memória
checkstatus4=$(/usr/local/bin/java-heap-incremental)
if [ -z "$checkstatus4" ]; then
         echo "Mailboxd Running" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt

else
         echo "$checkstatus4"
         echo "Mailboxd Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
         echo "Mailboxd Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/$nomearquivo
fi
# Verifica se o tamanho da fila ultrapassou de 1000 mensagens retidas
alerta_sobre_fila=$(alerta_de_fila 1000)
if [ -z "$alerta_sobre_fila" ]; then
         echo "Fila Running" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
else
         echo "Fila Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/status.txt
         echo "Fila Stopped" >> /opt/zextras/mailboxd/webapps/zimbra/$nomearquivo
fi

# Ricardo - ServerDo.in - 2024-09-20 - Em algumas versões de carbonio sem proxy, o arquivo status vai estar acessível outro endereço, por isso vamos salvar uma cópia do arquivo aqui também
cp /opt/zextras/mailboxd/webapps/zimbra/status.txt /opt/zextras/data/nginx/html/
EOF

# Concede permissão de execução
chmod +x /opt/serverdoin/scripts/checkcarboniostatus.sh

# Ricardo - ServerDo.in - 2024-10-03 - alerta_de_fila precisa do boxes instalado
apt install -y boxes

cat << 'EOF' > /usr/local/bin/alerta_de_fila
#!/bin/bash
limit_active=$1
limit_deferred=$2
if [[ $limit_active = '' ]] && [[ $limit_deferred = '' ]]; then
        echo -e "ALERTA!!! Não há configuração dos alertas de fila do carbonio no(a) $(hostname -s)" | boxes -d shell -p a1v1
else
        qnt_mensagens_active=$(($(sudo /opt/zextras/libexec/zmqstat | grep 'active\|incoming\|hold' | cut -f 2 -d "=" | tr '\n' '+' | sed 's/.$//g')))
        qnt_mensagens_deferred=$(($(sudo /opt/zextras/libexec/zmqstat | grep 'deferred\|corrupt' | cut -f 2 -d "=" | tr '\n' '+' | sed 's/.$//g')))
        if [[ $limit_deferred = '' ]]; then
                limit_deferred=$1
        fi
        if [ $qnt_mensagens_active -gt $limit_active ]; then
                echo -e "ALERTA!!! $(date +%d/%m/%y" "%H:%M)\n\nO tamanho da fila ACTIVE do Carbonio no(a) $(hostname -s) excedeu o limite de $limit_active: $qnt_mensagens_active" | boxes -d shell -p a1v1
        fi
        if [ $qnt_mensagens_deferred -gt $limit_deferred ]; then
                echo -e "ALERTA!!! $(date +%d/%m/%y" "%H:%M)\\n\nO tamanho da fila DEFERRED do Carbonio no(a) $(hostname -s) excedeu o limite de $limit_deferred: $qnt_mensagens_deferred" | boxes -d shell -p a1v1
        fi
        if [[ $qnt_mensagens_active -gt $limit_active ]] || [[ $qnt_mensagens_deferred -gt $limit_deferred ]]; then
                filas=$(sudo /opt/zextras/libexec/zmqstat | tr '\n' ' ')
                echo -e "\n"$filas
        fi
fi
EOF

# Concede permissão de execução
chmod +x /usr/local/bin/alerta_de_fila

cat << 'EOF' > /opt/serverdoin/scripts/check-status.sh
#!/bin/bash

# Ricardo - 2024-09-21 - Criando pela API já que o Auto Provision não está sempre habilitado
curl https://checks.serverdo.in/api/v1/checks/ \
    --header "X-Api-Key: 3AhrdyDBjrmjqGI-vDCfPQN868uGYfEz" \
    --data "{\"name\": \"$(hostname -s)\", \"tags\": \"$(hostname -s)\", \"timeout\": 900, \"grace\": 300, \"channels\": \"ac4cf9e8-4153-49cc-bc8d-016389ba14a5\", \"unique\": [\"name\"]}"

STATUS=$(cat /opt/zextras/jetty_base/webapps/zimbra/status.txt | grep -i "stop\|not")

if [[ -z $STATUS ]]; then
        curl https://checks.serverdo.in/ping/DDqrFAj_o5zpYhVEODGdnQ/$(hostname -s)
else
        curl https://checks.serverdo.in/ping/DDqrFAj_o5zpYhVEODGdnQ/$(hostname -s)/fail
fi
EOF

# Concede permissão de execução
chmod +x /opt/serverdoin/scripts/check-status.sh

# Fazendo o status.txt responder pelo nginx
cp /opt/zextras/conf/nginx/templates/nginx.conf.web.https.default.template   /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.default.template
cp /opt/zextras/conf/nginx/templates/nginx.conf.web.https.template   /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.template

chown zextras:zextras /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.default.template
chown zextras:zextras /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.template

sed -i '/location = \/favicon\.ico/i \
location = /status.txt { \
    root /opt/zextras/jetty_base/webapps/zimbra/; \
}' /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.default.template

sed -i '/location = \/favicon\.ico/i \
location = /status.txt { \
    root /opt/zextras/jetty_base/webapps/zimbra/; \
}' /opt/zextras/conf/nginx/templates_custom/nginx.conf.web.https.template

su - zextras -c "zmcontrol restart"

# Pegando o ID para enviar por e-mail. É preciso fazer uma chamada no checks para registrar
RESPONSE=$(curl https://checks.serverdo.in/api/v1/checks/ \
     --header "X-Api-Key: 2yvcQg2R960ps5Zwm4DFAkjNrgT0fQ73" \
     --data "{\"name\": \"$(hostname -s)\", \"tags\": \"$(hostname -s)\", \"timeout\": 900, \"grace\": 300, \"channels\": \"9c1d78da-7d77-434a-888a-7558d13986a5\", \"unique\": [\"name\"]}")
# Extrair o UUID do campo 'ping_url' no JSON de retorno
UUID=$(echo $RESPONSE | grep -oP '(?<=ping/)[^"]+')

# Ajustando o cron
# No futuro podemos ao invés de colocar em /etc/crontab, colocar em /etc/cron.d/serververdoin-cron-carbonio - só precisaria ajustar e colocar o começo do arquivo
echo "
## Acompanhamento de envio de e-mail - Cron comentada. Deve se buscar o e-mail para envio em checks.serverdo.in
*/5 * * * *     root    echo \"Envio de $(hostname -s)\" | sendmail ${UUID}@checks.serverdo.in > /dev/null 2>&1
" >> /etc/crontab

cat << 'EOF' >> /etc/crontab

## Acompanhamento de fila de e-mail
*/5 * * * *     root    /bin/bash /usr/local/bin/alerta_de_fila 100 100

## Reboota apos 15 minutos
@reboot zextras sleep 900 && /opt/zextras/bin/carbonio prov restart > /dev/null 2>&1

## Checagem do zmprov status
*/5 * * * *     root    /bin/bash /opt/serverdoin/scripts/checkcarboniostatus.sh > /dev/null 2>&1
*/5 * * * *     root    /bin/bash /opt/serverdoin/scripts/check-status.sh > /dev/null 2>&1

# Adicionando a chamado do pending-setups para o carbonio após o horário do update e upgrade do apt. Assim caso precise de um finalização de atualização era será chamada de maneira automática - 2024-10-01 - Ricardo ServerDo.in
0 3 * * 6      root    SETUP_CONSUL_TOKEN=$(cat /root/.carbonio) /usr/bin/pending-setups --execute-all
EOF