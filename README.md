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
I tried configuring Falco but it looks like it was not present in the Edera environment by default:
```
curl -sSL https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/falco.yaml | sudo tee /etc/falco/falco.yaml > /dev/null
```

Let's start by adding the Falco ```GPG key``` and associated ```repository```:
```
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /etc/apt/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
```

As always, we need to update the package lists before installing Falco:
```
sudo apt-get update
sudo apt-get install -y falco
```

Now that ```/etc/falco/``` exists, we can run ```curl``` again:
```
curl -sSL https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/falco.yaml | sudo tee /etc/falco/falco.yaml > /dev/null
```

We also need to download our falco rules to ```/etc/falco/falco_rules.yaml```:
```
curl -sSL https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/falco_rules.yaml | sudo tee /etc/falco/falco_rules.yaml > /dev/null
```
Run this command to append the standard output config to the end of ```/etc/falco/falco.yaml```:
```
echo -e "\nstdout_output:\n  enabled: true" | sudo tee -a /etc/falco/falco.yaml > /dev/null
```

Now, restart the background service and run Falco in ```debug``` mode:
```
sudo systemctl restart falco
sudo falco -o "log_level=debug"
```

You should see Falco initialise, load the ```edera``` plugin, connect to ```/var/lib/edera/protect/daemon.socket```, and wait for zone events!
