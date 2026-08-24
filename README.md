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

Check and remove duplicate sessions:
```
tmux ls
tmux kill-session -t edera
```

## Configuring Falco

Append ```load_plugins``` directly to your main config file:
```
echo "load_plugins: [edera]" | sudo tee -a /etc/falco/falco.yaml > /dev/null
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

Reload ```systemd``` and restart Falco to apply the override:
```
sudo systemctl daemon-reload
sudo systemctl restart falco
```

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

## Automating Falco
```
wget https://raw.githubusercontent.com/ndouglas-edera/tmux-falco/refs/heads/main/install-falco-edera-v5.sh
chmod +x install-falco-edera-v5.sh
```

Run the automation script:
```
sudo ./install-falco-edera-v5.sh
```

## Testing Falco Rules

In **Tab A**:
```
sudo cat /etc/shadow >/dev/null
```

In **Tab B**:
```
sudo journalctl -u falco-modern-bpf.service -f
```

<img width="1506" height="856" alt="Screenshot 2026-08-23 at 23 11 55" src="https://github.com/user-attachments/assets/a026bcb7-c652-4247-8ef9-8d01b8c88bbb" />

Confirm the **5** custom Falco rules are present:
```
grep '^- rule:' /etc/falco/rules.d/falco-edera-rules.yaml
```

In **Tab B**:
```
sudo journalctl -u falco-modern-bpf.service -f -n 0 -o cat | awk '
  /Critical/ { print "\033[1;31m" $0 "\033[0m"; next }
  /Warning/  { print "\033[1;33m" $0 "\033[0m"; next }
  /Notice/   { print "\033[1;34m" $0 "\033[0m"; next }
  /Error/    { print "\033[1;31m" $0 "\033[0m"; next }
'
```

In **Tab A**:

**[Rule 1](https://docs.edera.dev/guides/observability/falco-integration/#detect-credential-harvesting-via-procfs): Detect credential harvesting via procfs** <br/>
Reads ```/proc/1/environ``` to trigger the ```procfs``` credential harvesting detection.
```
sudo protect workload launch \
  --zone test-zone \
  --name alpine-shell \
  -t -a \
  docker.io/library/alpine:latest sh -c "cat /proc/1/environ"
```

**[Rule 2](https://docs.edera.dev/guides/observability/falco-integration/#detect-reverse-shells-and-suspicious-network-tools): Detect reverse shells and suspicious network tools** <br/>
Executes ```nc``` (netcat) to trigger the reverse shell tool detection.
```
sudo protect workload launch \
  --zone test-zone \
  --name alpine-shell \
  -t -a \
  docker.io/library/alpine:latest sh -c "nc -h"
```

**[Rule 3](https://docs.edera.dev/guides/observability/falco-integration/#detect-namespace-escape-attempts): Detect namespace escape attempts** <br/>
Attempts to run ```nsenter``` to trigger the namespace escape detection.
```
sudo protect workload launch \
  --zone test-zone \
  --name alpine-shell \
  -t -a \
  docker.io/library/alpine:latest sh -c "nsenter -h"
```

**[Rule 4](https://docs.edera.dev/guides/observability/falco-integration/#detect-sensitive-file-reads): Detect sensitive file reads** <br/>
Attempts to read ```/etc/shadow``` to trigger the sensitive file access detection.
```
sudo protect workload launch \
  --zone test-zone \
  --name alpine-shell \
  -t -a \
  docker.io/library/alpine:latest sh -c "cat /etc/shadow"
```

**[Rule 5](https://docs.edera.dev/guides/observability/falco-integration/#detect-outbound-network-connections): Detect outbound network connections** <br/>
Initiates an outbound network connection using ```nc``` to trigger the IPv4 socket connection detection. <br/>
**FUN FACT:** This command triggers both the ```reverse shell``` attempt AND an ```outbound connection``` rules.
```
sudo protect workload launch \
  --zone test-zone \
  --name alpine-shell \
  -t -a \
  docker.io/library/alpine:latest sh -c "nc -z 1.1.1.1 80"
```

<img width="1531" height="711" alt="Screenshot 2026-08-24 at 14 42 23" src="https://github.com/user-attachments/assets/83ab9a0c-c722-4717-beaf-6bd1383d151c" />

