#!/bin/bash -eux

# ../${HOSTNAME}/deploy.sh があればそちらを実行して終了
if [ -e ../${HOSTNAME}/deploy.sh ]; then
  ../${HOSTNAME}/deploy.sh
  exit 0
fi

# 各種設定ファイルのコピー
# ../${HOSTNAME}/env.sh があればそちらを優先してコピーする
if [ -e ../${HOSTNAME}/env.sh ]; then
  sudo cp -f ../${HOSTNAME}/env.sh /home/isucon/env.sh
else
  sudo cp -f env.sh /home/isucon/env.sh
fi

# etc以下のファイルについてすべてコピーする
for file in `\find etc -type f`; do
  # .gitkeepはコピーしない
  if [ $file = "etc/.gitkeep" ]; then
    continue
  fi

  # 同名のファイルが ../${HOSTNAME}/etc/ にあればそちらを優先してコピーする
  if [ -e ../${HOSTNAME}/$file ]; then
    sudo cp -f ../${HOSTNAME}/$file /$file
    continue
  fi
  sudo cp -f $file /$file
done

# アプリケーションのビルド
cd /home/isucon/private_isu/webapp/golang/

# もしpgo.pb.gzがあればPGOを利用してビルド
if [ -e pgo.pb.gz ]; then
  go build -o app -pgo=pgo.pb.gz
else
  go build -o app
fi


# ミドルウェア・Appの再起動
sudo systemctl restart mysql
sudo systemctl restart nginx
sudo systemctl restart isu-go

# slow query logの有効化
# QUERY="
# set global slow_query_log_file = '/var/log/mysql/mysql-slow.log';
# set global long_query_time = 0;
# set global slow_query_log = ON;
# "
# echo $QUERY | sudo mysql -uroot

# log permission
sudo chmod -R 777 /var/log/nginx
sudo chmod -R 777 /var/log/mysql
