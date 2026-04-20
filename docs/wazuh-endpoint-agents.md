# Wazuh endpoint agents

CMMC L2 expects monitoring on endpoints that process CUI — not only on
the appliance. When you deploy Open-CMMC with `--with-wazuh`, the VM
ships a Wazuh manager; point each operator workstation at it and a
single dashboard covers the appliance and every endpoint.

Throughout this doc, `wazuh.example.internal` stands in for the manager
hostname — replace with whatever resolves to your Open-CMMC VM (or
reuse the `$FB_HOSTNAME` you picked at install time).

## What the endpoint agent does for you

The pre-built configs in `config/wazuh/endpoints/` are opinionated for
the Open-CMMC use case: file-integrity monitoring on the folders where
CUI tends to land (Documents / Downloads / Desktop and any mounted
filebrowser share), rootcheck, and the Wazuh vulnerability detector.
Active response is **off** by default — automated endpoint isolation is
a lever operators should wire deliberately.

| Control | Endpoint evidence |
|---|---|
| 3.11.2 vulnerability scan | Syscollector inventory + Vulnerability Detector CVE correlation |
| 3.14.1 flaw remediation | Syscollector tracks installed versions; Wazuh alerts on new CVEs |
| 3.14.2 malicious code protection | Rootcheck + native AV events (Defender / ClamAV / XProtect) |
| 3.14.3 monitor alerts | Authentication + account-lifecycle events from OS logs |
| 3.4.1 / 3.4.3 configuration management | FIM on system binary dirs |

## Windows (10 / 11)

Elevated PowerShell:

```powershell
$v = "4.9.0-1"
$msi = "$env:TEMP\wazuh-agent-$v.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$v.msi" -OutFile $msi
msiexec.exe /i $msi /q `
  WAZUH_MANAGER="wazuh.example.internal" `
  WAZUH_AGENT_NAME="$env:COMPUTERNAME"
net start wazuh-agent
```

Then drop `config/wazuh/endpoints/windows-ossec.conf` over
`C:\Program Files (x86)\ossec-agent\ossec.conf` and restart the service.
The config reads the Security / System / Application EventLogs and
FIM-watches OneDrive, Documents, Downloads, Desktop, the Recycle Bin,
`C:\Program Files`, and `C:\Windows\System32`.

## Linux (RHEL 9 / AlmaLinux 9)

```bash
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo tee /etc/yum.repos.d/wazuh.repo >/dev/null <<'EOF'
[wazuh]
name=Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
EOF

sudo WAZUH_MANAGER="wazuh.example.internal" \
     WAZUH_AGENT_NAME="$(hostname)" \
     dnf install -y wazuh-agent
sudo systemctl enable --now wazuh-agent
```

Drop `config/wazuh/endpoints/linux-ossec.conf` over
`/var/ossec/etc/ossec.conf`. It pulls from `/var/log/secure`,
`/var/log/audit/audit.log`, and journald for auth / sudo / SELinux, and
FIMs `$HOME/Documents`, `$HOME/Downloads`, any filebrowser mount,
`/etc`, and the binary dirs.

## macOS (14+)

```bash
curl -Lo /tmp/wazuh-agent.pkg \
  https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.0-1.arm64.pkg
sudo installer -pkg /tmp/wazuh-agent.pkg -target /
sudo /Library/Ossec/bin/agent-auth -m wazuh.example.internal -A "$(hostname)"
sudo /Library/Ossec/bin/wazuh-control start
```

Drop `config/wazuh/endpoints/macos-ossec.conf` over
`/Library/Ossec/etc/ossec.conf`. Uses the unified log for auth / user /
security subsystems and FIMs `~/Documents`, `~/Downloads`, `~/Desktop`,
`/Applications`, `/usr/local/bin`, `/etc`.

## Enrollment hardening

The snippets above use password-based enrollment — fine for a dev
cabinet, but rotate to certificate-based enrollment before a CMMC
assessment. Generate a per-site CA + client cert on the manager:

```bash
sudo /var/ossec/bin/manage_agents
```

Distribute the client cert through your device-provisioning pipeline
(MDM / Intune / Jamf / Salt / Ansible) and close port `1515/tcp` to
anything but the enrollment network. Full flow is in the
[Wazuh documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html).

## Evidence for the SSP

The dashboard's **Agents** view lists every endpoint — last-seen,
version, OS, and health. Export it once per quarter and attach to the
SSP as the endpoint-monitoring attestation for 3.11.2, 3.14.1, and
3.14.2.
