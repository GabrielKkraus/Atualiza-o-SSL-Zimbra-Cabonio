## 🔐 Emissão e Renovação Automática de Certificado SSL com acme.sh para Zimbra-Cabonio

Este projeto contém um script shell para emissão e renovação automática de certificados SSL gratuitos utilizando o cliente [acme.sh](https://github.com/acmesh-official/acme.sh) e a autoridade certificadora ZeroSSL (ou Let's Encrypt).

### ✔️ Funcionalidades do script

- Para temporariamente serviços que ocupam a porta 80 (como Nginx ou servidores de e-mail) para permitir a validação HTTP.
- Instala automaticamente o `acme.sh` se não estiver presente no sistema.
- Emite ou renova certificados SSL no modo `--standalone`.
- Reinicia os serviços após a emissão do certificado.
- Armazena os certificados em um diretório padrão do `acme.sh`.

### 🔄 Renovação automática via cron

Uma tarefa `cron` pode ser configurada para executar o script periodicamente. Exemplo para rodar no dia 1º de cada mês às 03:00:

```cron
0 3 1 * * /opt/seucaminho/scripts/renova_certificado.sh >> /var/log/renova_certificado.log 2>&1
