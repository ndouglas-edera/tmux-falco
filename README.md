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

Append ```load_plugins``` directly to your main config file:
```
echo "load_plugins: [edera]" | sudo tee -a /etc/falco/falco.yaml > /dev/null
```

Now, restart the background service and run Falco in ```debug``` mode:
```
sudo systemctl restart falco
sudo falco -o "log_level=debug"
```

You should see Falco initialise, load the ```edera``` plugin, connect to ```/var/lib/edera/protect/daemon.socket```, and wait for zone events!
<br/><br/>
Run Falco with ```--disable-driver``` and streaming enabled. <br/>
Leave this run in a separate window will show every rule alert live from the **[./run-edera-demo.sh](https://github.com/ndouglas-edera/EderaOn-quickstart#edera-automated-script)** script executes:
```
sudo falco --disable-driver -o "log_level=info"
```

Since Falco runs as a background service (```falco.service```), you can tail its output live using ```journalctl``` while running your test script:
```
sudo systemctl restart falco
sudo journalctl -u falco -f -o cat
```

Check if the falco ```service``` died:
```
sudo systemctl status falco -l
```

Edit falco service via ```vim```:
```
sudo SYSTEMD_EDITOR=vim systemctl edit falco
```

Create the drop-in override directory and file directly using a single command:
```
sudo mkdir -p /etc/systemd/system/falco-modern-bpf.service.d/ && printf "[Service]\nExecStart=\nExecStart=/usr/bin/falco --disable-driver\n" | sudo tee /etc/systemd/system/falco-modern-bpf.service.d/override.conf > /dev/null
```

Reload systemd and restart Falco to apply the override:
```
sudo systemctl daemon-reload
sudo systemctl restart falco
```


Restore package default rules
```
sudo apt-get install --reinstall -o Dpkg::Options::="--force-confask" falco
```

## Second attempt Falco (automation)

Cleanup/remove Falco
```
falco --version
sudo systemctl stop falco 2>/dev/null || true
sudo apt-get remove --purge -y falco
sudo apt-get autoremove -y
sudo find /etc/falco -maxdepth 2 -type f -print 2>/dev/null
sudo mv /etc/falco /etc/falco.backup.$(date +%Y%m%d-%H%M%S)
systemctl status falco --no-pager
```

Reinstall Falco
```
sudo apt-get update
sudo apt-get install -y falco
falco --version
sudo ls -l /etc/falco/falco.yaml
```

Configure the Edera plugin:
```
sudo mkdir -p /etc/falco/config.d
```

Read the file / check it exists:
```
cat /etc/falco/config.d/falco-edera-config.yaml
```

Now, verify that the Edera library actually exists:
```
sudo ls -lh /var/lib/edera/protect/falco/libedera_falco_plugin.so
```

Automating Falco
```
wget https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/install-falco-edera.sh
chmod +x install-falco-edera.sh
```

Run the automation script:
```
sudo ./install-falco-edera.sh
```
