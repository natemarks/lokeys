#!/usr/bin/env bash
cp ~/.lokeys/insecure/jjj/jjj.txt ~/jjj/jjj.txt
sudo umount "${HOME}/.lokeys/insecure"
rm -f ~/.config/lokeys
rm -rf ~/.lokeys
