#!/bin/bash

# Script de Instalação Automática do Mattermost no Ubuntu 24.04 LTS
# Baseado na documentação oficial do Mattermost

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Verificações iniciais
check_requirements() {
    log "Verificando requisitos do sistema..."
    
    # Verificar se é Ubuntu 24.04
    if ! grep -q "Ubuntu 24.04" /etc/os-release; then
        error "Este script é específico para Ubuntu 24.04 LTS"
    fi
    
    # Verificar se é executado como root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root (sudo)"
    fi
    
    # Verificar memória RAM (mínimo 2GB)
    total_mem=$(free -m | awk 'NR==2{printf "%.0f", $2/1024}')
    if [ "$total_mem" -lt 2 ]; then
        warn "Sistema com menos de 2GB RAM. Recomendado: 2GB+ para até 1000 usuários"
    fi
    
    log "Requisitos verificados com sucesso!"
}

# Configuração de variáveis
setup_variables() {
    log "Configurando variáveis..."
    
    # Diretórios
    MATTERMOST_HOME="/opt/mattermost"
    MATTERMOST_DATA="/opt/mattermost/data"
    
    # Usuário do sistema
    MATTERMOST_USER="mattermost"
    
    # Database
    DB_NAME="mattermost"
    DB_USER="mmuser"
    DB_PASSWORD=$(openssl rand -base64 32)
    
    # Domínio local
    LOCAL_DOMAIN="1ri.local"
    
    log "Variáveis configuradas!"
}

# Atualização do sistema
update_system() {
    log "Atualizando sistema..."
    apt update -y
    apt upgrade -y
    apt install -y wget curl unzip postgresql postgresql-contrib nginx certbot python3-certbot-nginx ufw
    log "Sistema atualizado!"
}

# Configuração do PostgreSQL
setup_postgresql() {
    log "Configurando PostgreSQL..."
    
    # Iniciar e habilitar PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Criar usuário e banco de dados
    sudo -u postgres createuser --pwprompt $DB_USER <<EOF
$DB_PASSWORD
$DB_PASSWORD
EOF
    
    sudo -u postgres createdb -O $DB_USER $DB_NAME
    
    # Configurar PostgreSQL
    PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | grep -oP '\d+\.\d+' | head -1)
    PG_CONFIG="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
    PG_HBA="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
    
    # Backup das configurações originais
    cp $PG_CONFIG $PG_CONFIG.backup
    cp $PG_HBA $PG_HBA.backup
    
    # Configurar postgresql.conf
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" $PG_CONFIG
    sed -i "s/#port = 5432/port = 5432/" $PG_CONFIG
    
    # Configurar pg_hba.conf para autenticação md5
    sed -i "s/local   all             all                                     peer/local   all             all                                     md5/" $PG_HBA
    
    # Reiniciar PostgreSQL
    systemctl restart postgresql
    
    log "PostgreSQL configurado com sucesso!"
}

# Criar usuário do sistema
create_mattermost_user() {
    log "Criando usuário do sistema..."
    
    if ! id "$MATTERMOST_USER" &>/dev/null; then
        useradd --system --user-group --home-dir $MATTERMOST_HOME --shell /bin/false $MATTERMOST_USER
        log "Usuário $MATTERMOST_USER criado!"
    else
        log "Usuário $MATTERMOST_USER já existe!"
    fi
}

# Adicionar repositório e instalar Mattermost
install_mattermost() {
    log "Configurando repositório e instalando Mattermost..."
    
    # Remover chave antiga se existir
    rm -f /usr/share/keyrings/mattermost-archive-keyring.gpg
    
    # Adicionar chave GPG do repositório Mattermost
    log "Adicionando chave GPG do Mattermost..."
    curl -sL -o- https://deb.packages.mattermost.com/pubkey.gpg | gpg --dearmor | tee /usr/share/keyrings/mattermost-archive-keyring.gpg > /dev/null
    
    # Configurar repositório
    log "Configurando repositório Mattermost..."
    curl -o- https://deb.packages.mattermost.com/repo-setup.sh | bash -s mattermost
    
    # Atualizar lista de pacotes
    apt update
    
    # Instalar Mattermost (última versão disponível)
    log "Instalando Mattermost via APT..."
    apt install -y mattermost
    
    # O APT instala em /opt/mattermost por padrão
    MATTERMOST_HOME="/opt/mattermost"
    
    # Criar diretório de dados se não existir
    mkdir -p $MATTERMOST_DATA
    
    # Verificar se a instalação foi bem-sucedida
    if [ -f "$MATTERMOST_HOME/bin/mattermost" ]; then
        log "Mattermost instalado com sucesso via repositório oficial!"
        MATTERMOST_VERSION=$($MATTERMOST_HOME/bin/mattermost version | head -1 | awk '{print $2}')
        log "Versão instalada: $MATTERMOST_VERSION"
    else
        error "Falha na instalação do Mattermost"
    fi
}

# Configurar Mattermost
configure_mattermost() {
    log "Configurando Mattermost..."
    
    CONFIG_FILE="$MATTERMOST_HOME/config/config.json"
    
    # Backup da configuração original se existir
    if [ -f "$CONFIG_FILE" ]; then
        cp $CONFIG_FILE $CONFIG_FILE.backup
    fi
    
    # Configurar banco de dados
    sed -i "s/\"DataSource\": \".*\"/\"DataSource\": \"postgres:\/\/$DB_USER:$DB_PASSWORD@localhost:5432\/$DB_NAME?sslmode=disable\&connect_timeout=10\"/" $CONFIG_FILE
    sed -i "s/\"DriverName\": \"mysql\"/\"DriverName\": \"postgres\"/" $CONFIG_FILE
    
    # Configurar site URL para domínio local
    sed -i "s/\"SiteURL\": \"\"/\"SiteURL\": \"http:\/\/$LOCAL_DOMAIN\"/" $CONFIG_FILE
    
    # Configurar diretório de dados
    sed -i "s/\"Directory\": \"\.\/data\/\"/\"Directory\": \"$MATTERMOST_DATA\/\"/" $CONFIG_FILE
    
    # Configurar permissões corretas
    chown -R $MATTERMOST_USER:$MATTERMOST_USER $MATTERMOST_HOME
    chmod -R g+w $MATTERMOST_HOME
    
    log "Configuração do Mattermost concluída para domínio $LOCAL_DOMAIN!"
}

# Criar serviço systemd
create_systemd_service() {
    log "Criando serviço systemd..."
    
    cat > /etc/systemd/system/mattermost.service << EOF
[Unit]
Description=Mattermost
After=network.target
After=postgresql.service
Requires=postgresql.service

[Service]
Type=notify
ExecStart=$MATTERMOST_HOME/bin/mattermost
TimeoutStartSec=3600
KillMode=mixed
Restart=always
RestartSec=10
WorkingDirectory=$MATTERMOST_HOME
User=$MATTERMOST_USER
Group=$MATTERMOST_USER
LimitNOFILE=49152

[Install]
WantedBy=multi-user.target
EOF

    # Recarregar systemd e habilitar serviço
    systemctl daemon-reload
    systemctl enable mattermost
    
    log "Serviço systemd criado e habilitado!"
}

# Configurar Nginx
configure_nginx() {
    log "Configurando Nginx para domínio local..."
    
    # Remover configuração padrão
    rm -f /etc/nginx/sites-enabled/default
    
    # Criar configuração do Mattermost para domínio local
    cat > /etc/nginx/sites-available/mattermost << EOF
upstream backend {
    server 127.0.0.1:8065;
    keepalive 32;
}

proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=mattermost_cache:10m max_size=3g inactive=120m use_temp_path=off;

server {
    listen 80;
    server_name $LOCAL_DOMAIN;

    location ~ /api/v[0-9]+/(users/)?websocket$ {
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        client_max_body_size 50M;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Frame-Options SAMEORIGIN;
        proxy_buffers 256 16k;
        proxy_buffer_size 16k;
        client_body_timeout 60;
        send_timeout 300;
        lingering_timeout 5;
        proxy_connect_timeout 90;
        proxy_send_timeout 300;
        proxy_read_timeout 90s;
        proxy_pass http://backend;
    }

    location / {
        client_max_body_size 50M;
        proxy_set_header Connection "";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Frame-Options SAMEORIGIN;
        proxy_buffers 256 16k;
        proxy_buffer_size 16k;
        proxy_read_timeout 600s;
        proxy_cache mattermost_cache;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 2;
        proxy_cache_use_stale timeout;
        proxy_cache_lock on;
        proxy_http_version 1.1;
        proxy_pass http://backend;
    }
}
EOF

    # Habilitar site
    ln -sf /etc/nginx/sites-available/mattermost /etc/nginx/sites-enabled/
    
    # Criar diretório de cache
    mkdir -p /var/cache/nginx
    chown -R www-data:www-data /var/cache/nginx
    
    # Testar configuração
    nginx -t
    
    # Reiniciar Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    log "Nginx configurado para $LOCAL_DOMAIN!"
}

# Configurar firewall
configure_firewall() {
    log "Configurando firewall UFW..."
    
    # Habilitar UFW se não estiver
    ufw --force enable
    
    # Permitir SSH
    ufw allow ssh
    
    # Permitir HTTP e HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Permitir porta administrativa do Mattermost (apenas se necessário)
    # ufw allow 8065/tcp
    
    # Permitir SMTP saída
    ufw allow out 25/tcp
    ufw allow out 587/tcp
    ufw allow out 10025/tcp
    
    # Recarregar UFW
    ufw reload
    
    log "Firewall configurado!"
}

# Iniciar serviços
start_services() {
    log "Iniciando serviços..."
    
    # Iniciar Mattermost
    systemctl start mattermost
    
    # Aguardar inicialização
    sleep 10
    
    # Verificar status
    if systemctl is-active --quiet mattermost; then
        log "Mattermost iniciado com sucesso!"
    else
        error "Falha ao iniciar Mattermost. Verifique os logs: journalctl -u mattermost"
    fi
}

# Informações finais
show_final_info() {
    SERVER_IP=$(curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo "localhost")
    
    echo
    echo "=========================================="
    echo -e "${GREEN}INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
    echo "=========================================="
    echo
    echo "📋 INFORMAÇÕES DO SISTEMA:"
    echo "• Mattermost versão: $MATTERMOST_VERSION"
    echo "• Diretório: $MATTERMOST_HOME"
    echo "• Usuário do sistema: $MATTERMOST_USER"
    echo "• Banco de dados: PostgreSQL"
    echo
    echo "🌐 ACESSO:"
    echo "• URL: http://$SERVER_IP"
    echo "• Porta administrativa: http://$SERVER_IP:8065"
    echo
    echo "🔐 CREDENCIAIS DO BANCO:"
    echo "• Usuário: $DB_USER"
    echo "• Senha: $DB_PASSWORD"
    echo "• Banco: $DB_NAME"
    echo
    echo "📝 PRÓXIMOS PASSOS:"
    echo "1. Acesse http://$SERVER_IP para criar o primeiro administrador"
    echo "2. Configure SSL/TLS com: sudo certbot --nginx"
    echo "3. Ajuste as configurações em: $MATTERMOST_HOME/config/config.json"
    echo
    echo "🔧 COMANDOS ÚTEIS:"
    echo "• Status: sudo systemctl status mattermost"
    echo "• Logs: sudo journalctl -u mattermost -f"
    echo "• Reiniciar: sudo systemctl restart mattermost"
    echo
    echo "⚠️  IMPORTANTE: Salve as credenciais do banco de dados!"
    echo
}

# Função principal
main() {
    log "Iniciando instalação do Mattermost..."
    
    check_requirements
    setup_variables
    update_system
    setup_postgresql
    create_mattermost_user
    install_mattermost
    configure_mattermost
    create_systemd_service
    configure_nginx
    configure_firewall
    start_services
    show_final_info
    
    log "Instalação finalizada!"
}

# Executar instalação
main "$@"