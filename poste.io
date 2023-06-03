docker run \
--net=host \
-e TZ=Europe/Prague \
-v /home/mail:/data \
--name "mailserver" \
-h "mail.yuming.com" \
--restart=always \
-d analogic/poste.io
