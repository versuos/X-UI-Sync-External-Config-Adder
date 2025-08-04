#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate port
validate_port() {
    local port=$1
    if [[ ! $port =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}Invalid port number! Please enter a number between 1 and 65535.${NC}"
        exit 1
    fi
}

# Function to check if port is in use
check_port() {
    local port=$1
    if sudo netstat -tulnp | grep -q ":${port}"; then
        echo -e "${RED}Port ${port} is already in use!${NC}"
        exit 1
    fi
}

# Function to validate path
validate_path() {
    local path=$1
    if [[ ! $path =~ ^/[a-zA-Z0-9_-]+/$ ]]; then
        echo -e "${RED}Invalid path! Please enter a path starting and ending with '/' (e.g., /ss/).${NC}"
        exit 1
    fi
}

# Function to validate config
validate_config() {
    local config=$1
    if [ -z "$config" ]; then
        echo -e "${RED}Configuration cannot be empty!${NC}"
        exit 1
    fi
}

# Function to show menu
show_menu() {
    clear
    echo -e "${GREEN}=== V2Ray and 3X-UI Sync Manager Setup ===${NC}"
    echo "Please select an option:"
    echo "1) Install"
    echo "2) Configure"
    echo "3) Status"
    echo "4) Exit"
    read -p "Enter choice [1-4]: " choice
}

# Function to collect inputs
collect_inputs() {
    read -p "Enter your domain name (e.g., example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Domain name cannot be empty!${NC}"
        exit 1
    fi

    read -p "Enter Node.js server port (default: 3000): " NODE_PORT
    NODE_PORT=${NODE_PORT:-3000}
    validate_port "$NODE_PORT"
    check_port "$NODE_PORT"

    read -p "Enter Nginx SSL port (default: 8443): " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-8443}
    validate_port "$NGINX_PORT"

    read -p "Enter x-ui subscription port (default: 2096): " XUI_PORT
    XUI_PORT=${XUI_PORT:-2096}
    validate_port "$XUI_PORT"

    read -p "Enter subscription path (e.g., /ss/): " SUB_PATH
    SUB_PATH=${SUB_PATH:-/ss/}
    validate_path "$SUB_PATH"

    read -p "Do you have SSL certificates? (y/n): " HAS_SSL
    if [ "$HAS_SSL" = "y" ]; then
        read -p "Enter path to SSL certificate (e.g., /root/cert/example.com/fullchain.pem): " SSL_CERT
        if [ ! -f "$SSL_CERT" ]; then
            echo -e "${RED}SSL certificate file does not exist!${NC}"
            exit 1
        fi
        read -p "Enter path to SSL private key (e.g., /root/cert/example.com/privkey.pem): " SSL_KEY
        if [ ! -f "$SSL_KEY" ]; then
            echo -e "${RED}SSL private key file does not exist!${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}Installing Certbot to generate SSL certificates...${NC}"
        sudo apt install -y certbot python3-certbot-nginx
        sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@$DOMAIN
        SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
            echo -e "${RED}Failed to generate SSL certificates!${NC}"
            exit 1
        fi
    fi

    read -p "Enter external configuration (e.g., vless://..., vmess://..., etc.): " EXTERNAL_CONFIG
    validate_config "$EXTERNAL_CONFIG"

    read -p "Enter x-ui database path (default: /etc/x-ui/x-ui.db): " XUI_DB
    XUI_DB=${XUI_DB:-/etc/x-ui/x-ui.db}
    if [ ! -f "$XUI_DB" ]; then
        echo -e "${RED}x-ui database file does not exist!${NC}"
        exit 1
    fi

    read -p "Enter Telegram bot token: " TELEGRAM_BOT_TOKEN
    if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
        echo -e "${RED}Telegram bot token cannot be empty!${NC}"
        exit 1
    fi

    read -p "Enter Telegram chat ID: " TELEGRAM_CHAT_ID
    if [ -z "$TELEGRAM_CHAT_ID" ]; then
        echo -e "${RED}Telegram chat ID cannot be empty!${NC}"
        exit 1
    fi

    read -p "Enter sync interval in minutes (default: 10): " SYNC_INTERVAL
    SYNC_INTERVAL=${SYNC_INTERVAL:-10}
    if [[ ! $SYNC_INTERVAL =~ ^[0-9]+$ ]] || [ "$SYNC_INTERVAL" -lt 1 ]; then
        echo -e "${RED}Invalid sync interval! Please enter a positive number.${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Updating system and installing dependencies...${NC}"
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y curl nginx sqlite3 net-tools python3 python3-pip jq
    pip3 install python-telegram-bot==20.7 schedule

    if ! command_exists node; then
        echo -e "${YELLOW}Installing Node.js...${NC}"
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt install -y nodejs
    fi

    if ! command_exists pm2; then
        echo -e "${YELLOW}Installing PM2...${NC}"
        sudo npm install -g pm2
    fi
}

# Function to setup project directories and files
setup_projects() {
    V2RAY_DIR="/root/v2ray-sub-manager"
    SYNC_DIR="/opt/3x-ui-sync"
    echo -e "${YELLOW}Creating project directories...${NC}"
    mkdir -p "$V2RAY_DIR" "$SYNC_DIR"
    cd "$V2RAY_DIR" || exit 1

    echo -e "${YELLOW}Installing Node.js dependencies...${NC}"
    npm init -y
    npm install express axios sqlite3
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install Node.js dependencies!${NC}"
        exit 1
    fi

    # Create server.js
    echo -e "${YELLOW}Creating server.js...${NC}"
    cat > "$V2RAY_DIR/server.js" << EOL
const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const https = require('https');
const app = express();
const port = ${NODE_PORT};

const dbPath = '${XUI_DB}';
const externalConfig = '${EXTERNAL_CONFIG}';

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
  if (err) {
    console.error('Error connecting to x-ui database:', err.message);
  } else {
    console.log('Connected to x-ui database');
  }
});

async function getUserIds() {
  return new Promise((resolve, reject) => {
    db.all('SELECT settings FROM inbounds', (err, rows) => {
      if (err) {
        console.error('Error querying inbounds:', err.message);
        reject(err);
        return;
      }
      const userIds = [];
      rows.forEach(row => {
        try {
          const settings = JSON.parse(row.settings);
          if (settings.clients && Array.isArray(settings.clients)) {
            settings.clients.forEach(client => {
              if (client.subId && typeof client.subId === 'string') {
                userIds.push(client.subId);
              }
            });
          }
        } catch (error) {
          console.error('Error parsing settings JSON:', error.message);
        }
      });
      console.log('Fetched user IDs:', userIds);
      resolve(userIds);
    });
  });
}

app.get('${SUB_PATH}:userId', async (req, res) => {
  const userId = req.params.userId;
  console.log('Received request for userId:', userId);
  let configs = [externalConfig];

  try {
    const xuiResponse = await axios.get(\`https://127.0.0.1:${XUI_PORT}/sub/\${userId}\`, {
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      timeout: 5000
    });
    console.log('x-ui response status:', xuiResponse.status);
    console.log('x-ui response data:', xuiResponse.data);
    const xuiConfigs = Buffer.from(xuiResponse.data, 'base64').toString().split('\n').filter(c => c);
    configs = [...configs, ...xuiConfigs];
  } catch (error) {
    console.error(\`Error fetching x-ui configs for \${userId}:\`, error.message, error.response?.status, error.response?.data);
    configs = [externalConfig];
  }

  const configString = configs.join('\n');
  console.log('Generated configs:', configString);
  const encodedConfigs = Buffer.from(configString).toString('base64');
  res.send(encodedConfigs);
});

app.get('/users', async (req, res) => {
  try {
    const userIds = await getUserIds();
    console.log('Sending user IDs:', userIds);
    res.setHeader('Content-Type', 'application/json');
    res.json(userIds);
  } catch (error) {
    console.error('Error fetching users:', error.message);
    res.status(500).json({ error: \`Error fetching users: \${error.message}\` });
  }
});

app.listen(port, () => {
  console.log(\`Server running on http://127.0.0.1:\${port}\`);
}).on('error', (err) => {
  console.error('Server error:', err);
});
EOL

    # Create sync_xui.py
    echo -e "${YELLOW}Creating sync_xui.py...${NC}"
    cat > "$SYNC_DIR/sync_xui.py" << EOL
import sqlite3
import time
import schedule
from telegram import Bot, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, ConversationHandler, MessageHandler, filters
from datetime import datetime
import json
import logging
import asyncio
import re
import os

logging.basicConfig(filename='/opt/3x-ui-sync/sync_xui.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

with open('/opt/3x-ui-sync/config.json') as f:
    config = json.load(f)
    TELEGRAM_BOT_TOKEN = config['TELEGRAM_BOT_TOKEN']
    TELEGRAM_CHAT_ID = config['TELEGRAM_CHAT_ID']
    sync_interval = config['SYNC_INTERVAL']

DB_PATH = "/etc/x-ui/x-ui.db"
V2RAY_SERVER_PATH = "/root/v2ray-sub-manager/server.js"

is_sync_running = True
INPUT_INTERVAL, INPUT_CONFIG = range(2)

async def send_telegram_message(message):
    try:
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
        logging.info(f"Telegram message sent: {message}")
    except Exception as e:
        logging.error(f"Error sending Telegram message: {str(e)}")

def sync_users():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, inbound_id, email, up, down, expiry_time, enable FROM client_traffics")
        traffics = cursor.fetchall()
        cursor.execute("SELECT id, settings FROM inbounds")
        inbounds = cursor.fetchall()

        inbound_to_subid = {}
        inbound_to_total = {}
        for inbound_id, settings in inbounds:
            try:
                settings_json = json.loads(settings)
                clients = settings_json.get("clients", [])
                for client in clients:
                    sub_id = client.get("subId")
                    email = client.get("email")
                    total = client.get("total", 0)
                    if sub_id and email:
                        inbound_to_subid[(inbound_id, email)] = sub_id
                        inbound_to_total[(inbound_id, email)] = total
            except json.JSONDecodeError:
                logging.warning(f"Error parsing JSON for inbound_id: {inbound_id}")
                continue

        user_groups = {}
        for traffic in traffics:
            traffic_id, inbound_id, email, up, down, expiry_time, enable = traffic
            sub_id = inbound_to_subid.get((inbound_id, email))
            if sub_id:
                if sub_id not in user_groups:
                    user_groups[sub_id] = []
                user_groups[sub_id].append(traffic)

        logging.info(f"User groups: {user_groups}")

        for sub_id, group in user_groups.items():
            if len(group) > 1:
                max_up = max(traffic[3] for traffic in group if traffic[3] is not None)
                max_down = max(traffic[4] for traffic in group if traffic[4] is not None)
                max_expiry = max(traffic[5] for traffic in group if traffic[5] is not None)
                is_any_disabled = False
                for traffic in group:
                    traffic_id, inbound_id, email, up, down, expiry_time, enable = traffic
                    total = inbound_to_total.get((inbound_id, email), 0)
                    if total > 0 and (up + down) >= total:
                        is_any_disabled = True
                        break
                    current_time = int(time.time() * 1000)
                    if expiry_time > 0 and expiry_time <= current_time:
                        is_any_disabled = True
                        break
                    if enable == 0:
                        is_any_disabled = True
                        break
                for traffic in group:
                    traffic_id = traffic[0]
                    enable_status = 0 if is_any_disabled else 1
                    cursor.execute(
                        "UPDATE client_traffics SET up = ?, down = ?, expiry_time = ?, enable = ? WHERE id = ?",
                        (max_up, max_down, max_expiry, enable_status, traffic_id)
                    )
                logging.info(f"Synchronized for subId: {sub_id} - Status: {'Disabled' if is_any_disabled else 'Enabled'}")

        if user_groups:
            message = "Inbound traffic updated"
            asyncio.run(send_telegram_message(message))

        conn.commit()
        conn.close()
        logging.info("Synchronization completed successfully")
    except Exception as e:
        error_message = f"Error in synchronization: {str(e)}"
        logging.error(error_message)
        asyncio.run(send_telegram_message(error_message))

def update_external_config(new_config):
    try:
        if not new_config:
            raise ValueError("Configuration cannot be empty")
        with open(V2RAY_SERVER_PATH, 'r') as f:
            content = f.read()
        new_content = re.sub(r"const externalConfig = '[^']*';",
                            f"const externalConfig = '{new_config}';", content)
        with open(V2RAY_SERVER_PATH, 'w') as f:
            f.write(new_content)
        os.system('pm2 restart server')
        logging.info(f"External config updated: {new_config}")
        return True
    except Exception as e:
        logging.error(f"Error updating external config: {str(e)}")
        return False

async def start(update, context):
    keyboard = [
        [
            KeyboardButton("Start Sync"),
            KeyboardButton("Stop Sync"),
            KeyboardButton("Status"),
            KeyboardButton("Change Interval"),
            KeyboardButton("Change Config")
        ]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)
    await update.message.reply_text("Select an option:", reply_markup=reply_markup)
    return ConversationHandler.END

async def handle_button(update, context):
    global is_sync_running, sync_interval
    message_text = update.message.text

    if message_text == "Start Sync":
        is_sync_running = True
        schedule.clear()
        schedule.every(sync_interval).minutes.do(sync_users)
        await update.message.reply_text("Synchronization started.")
        logging.info("Synchronization started by user")
    elif message_text == "Stop Sync":
        is_sync_running = False
        schedule.clear()
        await update.message.reply_text("Synchronization stopped.")
        logging.info("Synchronization stopped by user")
    elif message_text == "Status":
        status = "Running" if is_sync_running else "Stopped"
        await update.message.reply_text(f"Status: {status}\nSync Interval: {sync_interval} minutes")
        logging.info(f"Status checked: {status}")
    elif message_text == "Change Interval":
        await update.message.reply_text("Enter new sync interval (in minutes):")
        return INPUT_INTERVAL
    elif message_text == "Change Config":
        await update.message.reply_text("Enter new external config (e.g., vless://..., vmess://..., etc.):")
        return INPUT_CONFIG
    return ConversationHandler.END

async def set_interval(update, context):
    global sync_interval, is_sync_running
    try:
        new_interval = int(update.message.text)
        if new_interval <= 0:
            await update.message.reply_text("Please enter a positive number.")
            return INPUT_INTERVAL
        sync_interval = new_interval
        with open('/opt/3x-ui-sync/config.json', 'r') as f:
            config = json.load(f)
        config['SYNC_INTERVAL'] = sync_interval
        with open('/opt/3x-ui-sync/config.json', 'w') as f:
            json.dump(config, f, indent=2)
        if is_sync_running:
            schedule.clear()
            schedule.every(sync_interval).minutes.do(sync_users)
        await update.message.reply_text(f"Sync interval changed to {sync_interval} minutes.")
        logging.info(f"Sync interval changed to {sync_interval} minutes")
        return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("Please enter a valid number.")
        return INPUT_INTERVAL

async def set_config(update, context):
    new_config = update.message.text
    if update_external_config(new_config):
        await update.message.reply_text(f"External config updated: {new_config}\nNode.js server restarted.")
        asyncio.run(send_telegram_message(f"External config updated: {new_config}"))
    else:
        await update.message.reply_text("Error: Invalid config or update failed.")
    return ConversationHandler.END

async def cancel(update, context):
    await update.message.reply_text("Operation cancelled.")
    return ConversationHandler.END

def run_schedule():
    while True:
        if is_sync_running:
            schedule.run_pending()
        time.sleep(1)

def main():
    schedule.every(sync_interval).minutes.do(sync_users)
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    conv_handler = ConversationHandler(
        entry_points=[
            MessageHandler(filters.Regex('^(Change Interval|Change Config)$'), handle_button)
        ],
        states={
            INPUT_INTERVAL: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_interval)],
            INPUT_CONFIG: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_config)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    application.add_handler(CommandHandler("start", start))
    application.add_handler(conv_handler)
    application.add_handler(MessageHandler(filters.Regex('^(Start Sync|Stop Sync|Status|Change Interval|Change Config)$'), handle_button))
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, run_schedule)
    application.run_polling()

if __name__ == "__main__":
    main()
EOL

    # Create config.json
    echo -e "${YELLOW}Creating config.json...${NC}"
    cat > "$SYNC_DIR/config.json" << EOL
{
  "TELEGRAM_BOT_TOKEN": "$TELEGRAM_BOT_TOKEN",
  "TELEGRAM_CHAT_ID": "$TELEGRAM_CHAT_ID",
  "SYNC_INTERVAL": $SYNC_INTERVAL
}
EOL

    # Set permissions
    chmod 600 "$SYNC_DIR/sync_xui.py" "$SYNC_DIR/config.json" "$V2RAY_DIR/server.js"
}

# Function to configure Nginx
configure_nginx() {
    echo -e "${YELLOW}Configuring Nginx...${NC}"
    sudo rm -f /etc/nginx/sites-enabled/* /etc/nginx/sites-available/*
    NGINX_CONFIG="/etc/nginx/sites-available/${DOMAIN}"
    sudo bash -c "cat > $NGINX_CONFIG << 'EOL'
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen ${NGINX_PORT} ssl;
    server_name ${DOMAIN};

    ssl_certificate ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};

    location ${SUB_PATH} {
        proxy_pass http://127.0.0.1:${NODE_PORT}${SUB_PATH};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /sub/ {
        proxy_pass https://127.0.0.1:${XUI_PORT}/sub/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL"

    sudo ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/
    sudo nginx -t
    if [ $? -ne 0 ]; then
        echo -e "${RED}Nginx configuration test failed! Check /var/log/nginx/error.log${NC}"
        sudo tail -n 20 /var/log/nginx/error.log
        exit 1
    fi
    sudo systemctl restart nginx
    sudo systemctl enable nginx
}

# Function to setup services
setup_services() {
    echo -e "${YELLOW}Setting up Systemd services...${NC}"
    cat > /etc/systemd/system/3x-ui-sync.service << EOL
[Unit]
Description=3X-UI User Sync Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 $SYNC_DIR/sync_xui.py
Restart=always
User=root
StandardOutput=append:/opt/3x-ui-sync/sync_xui.log
StandardError=append:/opt/3x-ui-sync/sync_xui.log

[Install]
WantedBy=multi-user.target
EOL

    systemctl enable 3x-ui-sync.service
    systemctl start 3x-ui-sync.service

    echo -e "${YELLOW}Starting Node.js server with PM2...${NC}"
    pm2 delete all 2>/dev/null || true
    cd "$V2RAY_DIR"
    pm2 start server.js
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start PM2! Check logs with 'pm2 logs'${NC}"
        sudo tail -n 20 ~/.pm2/logs/server-error.log
        exit 1
    fi
    pm2 save
    pm2 startup systemd
    sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u root --hp /root
    pm2 save
}

# Function to configure settings
configure_settings() {
    # Load existing settings if available
    if [ -f "/opt/3x-ui-sync/config.json" ]; then
        TELEGRAM_BOT_TOKEN=$(jq -r '.TELEGRAM_BOT_TOKEN' /opt/3x-ui-sync/config.json)
        TELEGRAM_CHAT_ID=$(jq -r '.TELEGRAM_CHAT_ID' /opt/3x-ui-sync/config.json)
        SYNC_INTERVAL=$(jq -r '.SYNC_INTERVAL' /opt/3x-ui-sync/config.json)
    fi
    if [ -f "/root/v2ray-sub-manager/server.js" ]; then
        EXTERNAL_CONFIG=$(grep "const externalConfig = " /root/v2ray-sub-manager/server.js | sed "s/const externalConfig = '//" | sed "s/';//")
    fi
    if [ -f "/etc/nginx/sites-available/$DOMAIN" ]; then
        NGINX_PORT=$(grep "listen .* ssl" /etc/nginx/sites-available/$DOMAIN | awk '{print $2}' | head -n 1)
        SUB_PATH=$(grep "location /" /etc/nginx/sites-available/$DOMAIN | grep -v "sub/" | awk '{print $2}' | head -n 1)
    fi
    if [ -f "/root/v2ray-sub-manager/server.js" ]; then
        NODE_PORT=$(grep "const port = " /root/v2ray-sub-manager/server.js | awk '{print $4}' | sed 's/;//')
    fi
    if [ -f "/root/v2ray-sub-manager/server.js" ]; then
        XUI_PORT=$(grep "axios.get(\`https://127.0.0.1:" /root/v2ray-sub-manager/server.js | sed -E "s/.*:([0-9]+).*/\1/")
    fi

    echo -e "${YELLOW}Current settings:${NC}"
    echo "Node.js Port: ${NODE_PORT:-Not set}"
    echo "Nginx SSL Port: ${NGINX_PORT:-Not set}"
    echo "X-UI Subscription Port: ${XUI_PORT:-Not set}"
    echo "Subscription Path: ${SUB_PATH:-Not set}"
    echo "Telegram Bot Token: ${TELEGRAM_BOT_TOKEN:-Not set}"
    echo "Telegram Chat ID: ${TELEGRAM_CHAT_ID:-Not set}"
    echo "Sync Interval: ${SYNC_INTERVAL:-Not set} minutes"
    echo "External Config: ${EXTERNAL_CONFIG:-Not set}"
    echo ""

    read -p "Enter new Node.js server port (leave blank to keep current: ${NODE_PORT:-3000}): " NEW_NODE_PORT
    if [ -n "$NEW_NODE_PORT" ]; then
        validate_port "$NEW_NODE_PORT"
        check_port "$NEW_NODE_PORT"
        NODE_PORT="$NEW_NODE_PORT"
    fi

    read -p "Enter new Nginx SSL port (leave blank to keep current: ${NGINX_PORT:-8443}): " NEW_NGINX_PORT
    if [ -n "$NEW_NGINX_PORT" ]; then
        validate_port "$NEW_NGINX_PORT"
        check_port "$NEW_NGINX_PORT"
        NGINX_PORT="$NEW_NGINX_PORT"
    fi

    read -p "Enter new X-UI subscription port (leave blank to keep current: ${XUI_PORT:-2096}): " NEW_XUI_PORT
    if [ -n "$NEW_XUI_PORT" ]; then
        validate_port "$NEW_XUI_PORT"
        check_port "$NEW_XUI_PORT"
        XUI_PORT="$NEW_XUI_PORT"
    fi

    read -p "Enter new subscription path (leave blank to keep current: ${SUB_PATH:-/ss/}): " NEW_SUB_PATH
    if [ -n "$NEW_SUB_PATH" ]; then
        validate_path "$NEW_SUB_PATH"
        SUB_PATH="$NEW_SUB_PATH"
    fi

    read -p "Enter new Telegram bot token (leave blank to keep current): " NEW_TOKEN
    if [ -n "$NEW_TOKEN" ]; then
        TELEGRAM_BOT_TOKEN="$NEW_TOKEN"
    fi

    read -p "Enter new Telegram chat ID (leave blank to keep current): " NEW_CHAT_ID
    if [ -n "$NEW_CHAT_ID" ]; then
        TELEGRAM_CHAT_ID="$NEW_CHAT_ID"
    fi

    read -p "Enter new sync interval in minutes (leave blank to keep current): " NEW_INTERVAL
    if [ -n "$NEW_INTERVAL" ]; then
        if [[ ! $NEW_INTERVAL =~ ^[0-9]+$ ]] || [ "$NEW_INTERVAL" -lt 1 ]; then
            echo -e "${RED}Invalid sync interval! Please enter a positive number.${NC}"
            exit 1
        fi
        SYNC_INTERVAL="$NEW_INTERVAL"
    fi

    read -p "Enter new external config (leave blank to keep current): " NEW_CONFIG
    if [ -n "$NEW_CONFIG" ]; then
        validate_config "$NEW_CONFIG"
        EXTERNAL_CONFIG="$NEW_CONFIG"
    fi

    # Update configuration files if needed
    if [ -n "$NEW_NODE_PORT" ] || [ -n "$NEW_NGINX_PORT" ] || [ -n "$NEW_XUI_PORT" ] || [ -n "$NEW_SUB_PATH" ] || [ -n "$NEW_CONFIG" ]; then
        if [ -f "$V2RAY_DIR/server.js" ]; then
            if [ -n "$NEW_NODE_PORT" ]; then
                sed -i "s/const port = [0-9]*;/const port = $NODE_PORT;/" "$V2RAY_DIR/server.js"
            fi
            if [ -n "$NEW_XUI_PORT" ]; then
                sed -i "s|axios.get(\`https://127.0.0.1:[0-9]*/sub/|axios.get(\`https://127.0.0.1:$XUI_PORT/sub/|" "$V2RAY_DIR/server.js"
            fi
            if [ -n "$NEW_SUB_PATH" ]; then
                sed -i "s|app.get('/[a-zA-Z0-9_-]*/:userId'|app.get('$SUB_PATH:userId'|" "$V2RAY_DIR/server.js"
            fi
            if [ -n "$NEW_CONFIG" ]; then
                sed -i "s|const externalConfig = '[^']*';|const externalConfig = '$EXTERNAL_CONFIG';|" "$V2RAY_DIR/server.js"
            fi
            cd "$V2RAY_DIR"
            pm2 restart server
        fi
        if [ -n "$NEW_NGINX_PORT" ] || [ -n "$NEW_SUB_PATH" ]; then
            configure_nginx
        fi
    fi

    if [ -n "$NEW_TOKEN" ] || [ -n "$NEW_CHAT_ID" ] || [ -n "$NEW_INTERVAL" ]; then
        cat > "$SYNC_DIR/config.json" << EOL
{
  "TELEGRAM_BOT_TOKEN": "$TELEGRAM_BOT_TOKEN",
  "TELEGRAM_CHAT_ID": "$TELEGRAM_CHAT_ID",
  "SYNC_INTERVAL": $SYNC_INTERVAL
}
EOL
        systemctl restart 3x-ui-sync.service
    fi
    echo -e "${GREEN}Settings updated successfully!${NC}"
}

# Function to check status
check_status() {
    echo -e "${YELLOW}Checking Nginx status...${NC}"
    sudo systemctl status nginx
    echo -e "${YELLOW}Checking 3x-ui-sync service status...${NC}"
    sudo systemctl status 3x-ui-sync.service
    echo -e "${YELLOW}Checking PM2 status...${NC}"
    pm2 status
    echo -e "${YELLOW}Testing users endpoint...${NC}"
    curl http://127.0.0.1:${NODE_PORT}/users
    echo ""
    echo -e "${YELLOW}Testing subscription endpoint (decoded)...${NC}"
    curl https://${DOMAIN}:${NGINX_PORT}${SUB_PATH}ind33qqa6pghbi5m --insecure | base64 -d
    echo ""
}

# Main loop
while true; do
    show_menu
    case $choice in
        1)
            echo -e "${YELLOW}Starting installation...${NC}"
            collect_inputs
            install_dependencies
            setup_projects
            configure_nginx
            setup_services
            echo -e "${GREEN}Installation completed successfully!${NC}"
            echo "Test subscription link: https://${DOMAIN}:${NGINX_PORT}${SUB_PATH}ind33qqa6pghbi5m"
            echo "Check logs: pm2 logs, sudo tail -f /var/log/nginx/error.log, tail -f /opt/3x-ui-sync/sync_xui.log"
            read -p "Press Enter to continue..."
            ;;
        2)
            echo -e "${YELLOW}Configuring settings...${NC}"
            configure_settings
            read -p "Press Enter to continue..."
            ;;
        3)
            echo -e "${YELLOW}Checking status...${NC}"
            check_status
            read -p "Press Enter to continue..."
            ;;
        4)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice! Please select 1-4.${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
done
