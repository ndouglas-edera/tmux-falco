# tmux Falco Environment
Simple demo setup of a terminal multiplexer running Edera Zones and Falco realtime detection
<br/><br/>
Install tmux (if not already installed):
```
sudo apt update && sudo apt install tmux -y
```
Create the config file:
```
vi ~/.tmux.conf
```
If ```tmux``` is running, reload it inside a session by pressing ```Ctrl+a``` then ```r```. Otherwise, start a new session:
```
tmux new -s edera
```

You can leave the session at any time with the ```exit``` command.

## Key Shortcuts Overview
- Prefix Key: ```Ctrl+a```
- Split Horizontally: ```Ctrl+a``` then ```|```
- Split Vertically: ```Ctrl+a``` then ```-```
- Navigate Panes: ```Ctrl+a``` then ```h```/```j```/```k```/```l```
- Resize Panes: ```Ctrl+a``` then ```Shift+H```/```J```/```K```/```L```
- New Window: ```Ctrl+a``` then ```c```
- Switch Window: ```Ctrl+a``` then ```1```, ```2```, etc.
- Detach Session: ```Ctrl+a``` then ```d```

## Configuring Falco
```
curl -sSL https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/falco.yaml | sudo tee /etc/falco/falco.yaml > /dev/null
```
