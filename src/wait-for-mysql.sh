#!/usr/bin/bash
for i in {1..300}; do
    echo "waiting for mysql... $i"; sleep 5;
    if mysqladmin ping -h "$DB_HOST" --silent --connect-timeout=2; then break; fi;
done;

if [ $i -eq 300 ]; then
    echo "waiting for mysql failed"
    exit 1
fi

[ -d "/app/uploads" ] || mkdir /app/uploads

while true; do
  nodemon -e js,pug  server.js 
done
