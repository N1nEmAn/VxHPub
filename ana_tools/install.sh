#!/bin/sh
# 安装依赖包
pip3 install --upgrade pip
pip3 install lzma
pip3 install gzip
pip3 install bz2file
pip3 install binwalk
pip3 install argparse
pip3 install pyvis
pip3 install matplotlib
# 安装可选依赖
pip3 install angr-utils

# echo -e "#!/bin/sh\n$(pwd)/main.py \$1" >/usr/bin/vxgraph
# sudo chmod 555 /usr/bin/vxgraph
# 获取当前 shell 名称
current_shell=$(basename "$SHELL")

# 设置 alias 命令
alias_command="alias vxana=\"$(pwd)/main.py\""

# 根据 shell 类型添加到相应的 rc 文件
case "$current_shell" in
bash)
  echo "$alias_command" >>~/.bashrc
  echo "Alias added to ~/.bashrc"
  ;;
zsh)
  echo "$alias_command" >>~/.zshrc
  echo "Alias added to ~/.zshrc"
  ;;
fish)
  echo "alias vxgraph $(pwd)/main.py" >>~/.config/fish/config.fish
  echo "Alias added to ~/.config/fish/config.fish"
  ;;
*)
  echo "Unsupported shell: $current_shell"
  ;;
esac
echo "OK! Enjoy your vxgraph!"
