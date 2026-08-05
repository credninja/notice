# Suricata Rules — Snapshot

This directory is a **snapshot** of the live Suricata rules from `/var/lib/suricata/rules/`, kept in the repo so they're version-controlled alongside the application code.

## Refreshing the snapshot

After an `update_rules.sh` run or after accepting a rule proposal:

    ./scripts/backup-rules.sh
    git add suricata-rules
    git commit -m "rules: snapshot $(date +%Y-%m-%d)"
    git push

The script preserves mtimes so `git diff` highlights actual content changes.

## Restoring rules from this snapshot

If the live rules dir is wiped or corrupted:

    sudo rsync -a --delete suricata-rules/ /var/lib/suricata/rules/
    sudo systemctl reload suricata

## What's here

- `*.rules` — Emerging Threats Pro / community / custom rule files
- `suricata.rules` — combined index (auto-generated; large)
- `classification.config`, `reference.config` — rule classification metadata
