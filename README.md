# Projeto de Análise de Vulnerabilidades e Testes de Força Bruta

## 1. Descrição do Desafio

Este projeto visa demonstrar a implementação e documentação de um cenário prático de análise de vulnerabilidades e execução de ataques de força bruta. Utilizamos o **Kali Linux** como plataforma de ataque e a ferramenta **Medusa**, em conjunto com ambientes vulneráveis como o **Metasploitable 2 (DVWA)**, simulando situações reais para exercitar medidas de prevenção.

Mesmo sem a execução prática devido a desafios técnicos no ambiente de desenvolvimento, este README detalha a concepção, os métodos propostos e a compreensão dos processos envolvidos na realização dos testes de segurança.

## 2. Objetivos de Aprendizagem Abordados

Através da concepção e documentação deste projeto, foram explorados os seguintes objetivos de aprendizagem:

* **Compreensão de Ataques de Força Bruta:** Entendimento dos princípios e métodos de ataques de força bruta em diferentes serviços (FTP, WEB, SMB).
* **Utilização Conceitual do Kali Linux e Medusa:** Compreensão da função e aplicação do Kali Linux como sistema operacional para auditoria de segurança e da ferramenta Medusa para ataques específicos de força bruta em um ambiente controlado.
* **Documentação de Processos:** Habilidade de documentar processos técnicos de forma clara e estruturada, essencial para a comunicação e replicabilidade de testes de segurança.
* **Reconhecimento de Vulnerabilidades:** Identificação de vulnerabilidades comuns e propostas de mitigação em serviços como FTP, WEB (DVWA) e SMB.
* **Utilização do GitHub para Portfólio Técnico:** Aplicação do GitHub como ferramenta para compartilhar documentação técnica, evidências conceituais e o código de apoio (scripts, wordlists).

## 3. Cenário Proposto e Metodologia

O desafio envolve a configuração de duas máquinas virtuais (VMs) no VirtualBox: uma para o Kali Linux (atacante) e outra para o Metasploitable 2 (vítima), ambas conectadas em uma rede interna (host-only).

### 3.1. Configuração do Ambiente (Conceitual)

* **Kali Linux (Máquina Atacante):**
    * Sistema operacional: Kali Linux (versão x.x)
    * Ferramentas principais: Medusa, ferramentas de rede (nmap)
    * Configuração de rede: Adaptador de rede Host-Only, IP estático (ex: 192.168.56.101)
* **Metasploitable 2 (Máquina Vítima):**
    * Sistema operacional: Linux (baseado em Ubuntu)
    * Serviços vulneráveis: FTP (vsftpd), Web (DVWA), SMB (Samba)
    * Configuração de rede: Adaptador de rede Host-Only, IP estático (ex: 192.168.56.102)

_**Nota:** Embora as VMs não tenham sido instaladas devido a limitações técnicas, a configuração acima representa o ambiente ideal para a execução do desafio._

### 3.2. Execução de Ataques Simulados (Conceitual)

Foram planejados os seguintes ataques de força bruta, detalhando as etapas e os comandos que seriam utilizados:

#### a) Força Bruta em FTP (File Transfer Protocol)

* **Objetivo:** Obter credenciais de acesso ao serviço FTP no Metasploitable 2.
* **Ferramenta:** Medusa no Kali Linux.
* **Metodologia:**
    1.  **Reconhecimento:** Usar `nmap` para identificar portas abertas e o serviço FTP no IP do Metasploitable 2.
        ```bash
        nmap -sV <IP_METASPLOITABLE>
        ```
    2.  **Preparação da Wordlist:** Utilizar uma wordlist de senhas comuns (ex: `rockyou.txt` do Kali Linux ou uma customizada).
    3.  **Ataque com Medusa:** Executar o Medusa para tentar adivinhar a senha de usuários conhecidos (ou enumerados) para o serviço FTP.
        ```bash
        medusa -h <IP_METASPLOITABLE> -u <USUARIO_FTP> -P <CAMINHO_PARA_WORDLIST_SENHAS> -M ftp
        ```
        *Exemplo de usuário comum no Metasploitable: `msfadmin`*
* **Imagens Ilustrativas:** ![Exemplo de ataque de força bruta em FTP usando Medusa](https://cdn.hashnode.com/res/hashnode/image/upload/v1727713805524/86b3bfa0-de7e-470d-8482-310a3aa5f37a.png)

#### b) Automação de Tentativas em Formulário Web (DVWA)

* **Objetivo:** Obter credenciais de acesso ao formulário de login do DVWA (Damn Vulnerable Web Application).
* **Ferramenta:** Medusa (com módulo HTTP POST) ou Burp Suite Intruder (para cenários mais avançados).
* **Metodologia:**
    1.  **Acesso ao DVWA:** Navegar até a página de login do DVWA no Metasploitable 2 via navegador do Kali Linux.
    2.  **Análise do Formulário:** Inspecionar o formulário de login para entender os parâmetros de submissão (username, password, token de segurança).
    3.  **Preparação:** Criar wordlists para usuários e senhas.
    4.  **Ataque com Medusa (Exemplo Conceitual HTTP POST):**
        ```bash
        medusa -h <IP_METASPLOITABLE> -u <USUARIO_WEB> -P <CAMINHO_PARA_WORDLIST_SENHAS> -m http -T 5 -F -d "POST /dvwa/login.php HTTP/1.1\r\nHost: <IP_METASPLOITABLE>\r\nUser-Agent: Mozilla/5.0 (...)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://<IP_METASPLOITABLE>/dvwa/login.php\r\nCookie: PHPSESSID=...; security=low\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: XX\r\n\r\nusername=<USUARIO_WEB>&password=<PASS>&Login=Login\r\n" -s "Login failed"
        ```
        * _**Observação:** O comando acima é um exemplo simplificado. A string HTTP POST completa precisaria ser capturada e adaptada de uma requisição real do navegador, incluindo cookies e tokens de sessão/segurança do DVWA._
        * _**Alternativa:** Para formulários web, ferramentas como o Burp Suite Intruder são geralmente mais adequadas e flexíveis, permitindo capturar a requisição, definir "points de ataque" para usuário e senha, e analisar as respostas para identificar logins bem-sucedidos._
* **Imagens Ilustrativas:** [Incluir aqui links para imagens do login do DVWA, ou burp suite/medusa em ação contra web forms, buscando na web, como esta](https://deltarisk.com/wp-content/uploads/2020/05/figure-18-1024x535.png)

#### c) Password Spraying em SMB (Server Message Block) com Enumeração de Usuários

* **Objetivo:** Identificar usuários válidos e suas senhas no serviço SMB do Metasploitable 2.
* **Ferramenta:** Medusa no Kali Linux.
* **Metodologia:**
    1.  **Enumeração de Usuários:** Usar ferramentas como `enum4linux` (ou Nmap scripts) para tentar enumerar usuários válidos no sistema.
        ```bash
        enum4linux -U <IP_METASPLOITABLE>
        ```
    2.  **Password Spraying:** Utilizar uma pequena wordlist de senhas comuns contra a lista de usuários enumerados (ou usuários padrão do Metasploitable). Password spraying tenta uma mesma senha contra vários usuários antes de tentar a próxima senha, para evitar bloqueios por muitas tentativas falhas em um único usuário.
        ```bash
        medusa -h <IP_METASPLOITABLE> -U <CAMINHO_PARA_WORDLIST_USUARIOS> -p <SENHA_COMUM> -M smb
        ```
        *Exemplos de usuários comuns no Metasploitable: `msfadmin`, `user`*
        *Exemplos de senhas comuns: `password`, `123456`, `admin`*
* **Imagens Ilustrativas:** [Incluir aqui links para imagens de enum4linux ou medusa em ação contra SMB, buscando na web, como esta](https://cybersapiens.com.au/wp-content/uploads/2024/11/image-showing-example-of-shared-folders-output-from-enum4linux-showing-directories-and-their-permissions-1024x592.png)

## 4. Testes e Recomendações de Mitigação

Para cada cenário de ataque, seriam documentados os resultados (usuários/senhas encontrados) e, crucialmente, as recomendações de mitigação.

### 4.1. Recomendações Gerais

* **Políticas de Senha Fortes:** Impor senhas complexas, com requisitos de tamanho mínimo, uso de caracteres especiais, números e letras maiúsculas/minúsculas.
* **Bloqueio de Contas (Account Lockout):** Configurar políticas de bloqueio de contas após um número limitado de tentativas de login falhas.
* **Autenticação Multifator (MFA):** Implementar MFA para todos os serviços, adicionando uma camada extra de segurança.
* **Monitoramento de Logs:** Monitorar logs de autenticação para detectar tentativas de força bruta e atividades anômalas.
* **Atualização e Patcheamento:** Manter sistemas operacionais, serviços e aplicações sempre atualizados com os últimos patches de segurança.
* **Renomeação de Contas Padrão:** Alterar os nomes de usuário padrão de serviços (ex: `admin`, `guest`) para dificultar a enumeração.
* **Firewall:** Configurar firewalls para limitar o acesso a serviços sensíveis apenas a IPs confiáveis.
* **Uso de Captchas/Rate Limiting:** Em formulários web, implementar CAPTCHAs e limitar o número de tentativas de login por IP em um período de tempo.

### 4.2. Recomendações Específicas por Serviço

* **FTP:** Desabilitar FTP anônimo, usar SFTP ou FTPS para criptografar o tráfego de credenciais e dados.
* **Web (DVWA):** Além das recomendações gerais, garantir que aplicações web utilizem frameworks seguros e sigam as melhores práticas de desenvolvimento seguro (OWASP Top 10).
* **SMB:** Desabilitar SMBv1, usar SMBv3, e restringir o acesso a compartilhamentos SMB apenas a usuários e grupos autorizados.

## 5. Arquivos Adicionais e Evidências

Esta seção seria dedicada a arquivos que complementam o projeto.

* **`wordlists/`**:
    * `wordlist_senhas_comuns.txt`: Wordlist customizada de senhas comuns.
    * `wordlist_usuarios_smb.txt`: Wordlist customizada de nomes de usuários para SMB.
* **`scripts/`**:
    * `enum_smb_users.sh`: Exemplo de script para enumeração de usuários SMB (se aplicável).
* **`images/`**:
    * Capturas de tela dos comandos sendo executados no Kali Linux.
    * Evidências de sucesso dos ataques (login efetuado).
    * Capturas de tela das configurações das VMs no VirtualBox.

_**Nota:** Devido à ausência de execução prática, esta pasta conteria imagens representativas encontradas na web que ilustram os conceitos e os comandos mencionados._

## 6. Reflexões e Aprendizado

Mesmo sem a execução completa, a pesquisa e a documentação deste desafio reforçaram a importância da segurança ofensiva para entender e mitigar riscos. Aprofundar-se nas ferramentas como Kali Linux e Medusa, e nos vetores de ataque como força bruta em diferentes protocolos, é fundamental para qualquer profissional de segurança. A capacidade de documentar e explicar esses processos é tão valiosa quanto a execução técnica.

---
