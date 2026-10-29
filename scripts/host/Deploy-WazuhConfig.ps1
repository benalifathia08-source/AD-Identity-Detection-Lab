# Deploy-WazuhConfig.ps1
# Pushes the version-controlled Wazuh content from this repo to the Wazuh server:
#   configs/wazuh/shared/<group>/agent.conf  ->  /var/ossec/etc/shared/<group>/agent.conf
#   rules/*.xml                              ->  /var/ossec/etc/rules/
# Validates every agent.conf with verify-agent-conf before installing anything, creates missing agent
# groups, validates rules with wazuh-analysisd -t and only then restarts the manager. If rule validation
# fails, the previous rule files are restored.

param(
    [string] $Server  = '192.168.145.128',
    [string] $User    = 'fathia',
    [string] $KeyPath = (Join-Path $env:USERPROFILE '.ssh\ftou7_lab')
)
$ErrorActionPreference = 'Stop'
$repo  = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$stage = '/tmp/wazuh-deploy'
$ssh   = @('-i', $KeyPath, '-o', 'BatchMode=yes', "$User@$Server")

ssh @ssh "rm -rf $stage && mkdir -p $stage/shared $stage/rules"
if ($LASTEXITCODE -ne 0) { throw 'Cannot reach the Wazuh server.' }

$groups = Get-ChildItem (Join-Path $repo 'configs\wazuh\shared') -Directory -ErrorAction SilentlyContinue
foreach ($g in $groups) {
    ssh @ssh "mkdir -p $stage/shared/$($g.Name)"
    scp -i $KeyPath -o BatchMode=yes -q (Join-Path $g.FullName 'agent.conf') "${User}@${Server}:$stage/shared/$($g.Name)/agent.conf"
    if ($LASTEXITCODE -ne 0) { throw "Copy failed for group $($g.Name)" }
}
$rules = Get-ChildItem (Join-Path $repo 'rules') -Filter *.xml -ErrorAction SilentlyContinue
foreach ($r in $rules) {
    scp -i $KeyPath -o BatchMode=yes -q $r.FullName "${User}@${Server}:$stage/rules/$($r.Name)"
    if ($LASTEXITCODE -ne 0) { throw "Copy failed for rule file $($r.Name)" }
}

$remote = @'
set -e
STAGE=/tmp/wazuh-deploy
OSSEC=/var/ossec
BACKUP=$(mktemp -d)
cp -a $OSSEC/etc/rules/. "$BACKUP/"

TESTLOG=$(mktemp)

# Validate every group config before touching anything: a broken agent.conf would be pushed to all
# agents in that group (wazuh-analysisd -t below only checks the manager's own config and rules)
for dir in $STAGE/shared/*/; do
  [ -f "$dir/agent.conf" ] || continue
  if ! $OSSEC/bin/verify-agent-conf -f "$dir/agent.conf" > "$TESTLOG" 2>&1; then
    echo "validation: agent.conf for group $(basename "$dir") is INVALID - nothing deployed"
    tail -5 "$TESTLOG"
    rm -f "$TESTLOG"
    exit 1
  fi
done
echo "agent.conf validation: OK"

for dir in $STAGE/shared/*/; do
  [ -d "$dir" ] || continue
  g=$(basename "$dir")
  [ "$g" = "default" ] || [ -d "$OSSEC/etc/shared/$g" ] || $OSSEC/bin/agent_groups -a -g "$g" -q
  install -o wazuh -g wazuh -m 660 "$dir/agent.conf" "$OSSEC/etc/shared/$g/agent.conf"
  echo "group $g: agent.conf deployed"
done

for f in $STAGE/rules/*.xml; do
  [ -f "$f" ] || continue
  install -o wazuh -g wazuh -m 660 "$f" "$OSSEC/etc/rules/$(basename "$f")"
  echo "rules: $(basename "$f") deployed"
done

if $OSSEC/bin/wazuh-analysisd -t > "$TESTLOG" 2>&1; then
  echo "rules validation: OK"
  systemctl restart wazuh-manager
  echo "manager restarted: $(systemctl is-active wazuh-manager)"
else
  echo "rules validation: FAILED - restoring previous rules"
  tail -20 "$TESTLOG"
  cp -a "$BACKUP/." $OSSEC/etc/rules/
  rm -f "$TESTLOG"
  exit 1
fi
rm -rf "$BACKUP" $STAGE "$TESTLOG"
'@
# PowerShell may prepend a UTF-8 BOM and use CRLF when piping; strip both so bash sees a clean script
($remote -replace "`r", '') | ssh @ssh "tr -d '\r' | sed '1s/^\xEF\xBB\xBF//' > /tmp/wazuh-deploy.sh && sudo bash /tmp/wazuh-deploy.sh; rc=`$?; rm -f /tmp/wazuh-deploy.sh; exit `$rc"
if ($LASTEXITCODE -ne 0) { throw 'Deployment failed; see output above.' }
