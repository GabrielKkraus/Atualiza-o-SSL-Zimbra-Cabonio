#!/bin/bash

# IP público ou local do servidor
meu_ip=$(curl -s http://checkip.amazonaws.com || hostname -I | awk '{print $1}')
echo "[INFO] IP detectado do servidor: $meu_ip"

# Obtém lista de domínios via usuário zextras
dominios=$(su - zextras -c "zmprov gad")
if [ -z "$dominios" ]; then
  echo "[ERRO] Não foi possível obter domínios via zmprov com o usuário zextras."
  exit 1
fi

echo "[INFO] Domínios gerenciados:"
echo "$dominios"

dom_list=""
for dominio in $dominios; do
  for sub in "" "mail." "webmail."; do
    fqdn="${sub}${dominio}"
    ip_resolvido=$(dig +short "$fqdn" | while read linha; do
      [[ "$linha" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$linha" && break
    done)

    if [ "$ip_resolvido" = "$meu_ip" ]; then
      dom_list+=" -d $fqdn"
      echo "[VALIDADO] $fqdn → $ip_resolvido"
    else
      echo "[IGNORADO] $fqdn → ${ip_resolvido:-NÃO RESOLVEU} (não aponta para $meu_ip)"
    fi
  done
done

if [ -z "$dom_list" ]; then
  echo "[ERRO] Nenhum domínio válido apontando para este servidor foi encontrado."
  exit 1
fi

echo "[INFO] Domínios válidos para este servidor: $dom_list"

# Parar serviços
echo "[INFO] Parando Nginx..."
systemctl stop nginx

echo "[INFO] Parando Zextras..."
su - zextras -c "zmcontrol stop"
