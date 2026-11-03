# TRACE API on Oracle Cloud Always Free

This runs the full Docker API, scanners and background jobs included, on Oracle Cloud's Always Free Arm VM. It is free with no time limit, and the VM has enough memory for real-repository scans.

## Why Oracle

The host was chosen from [free-for-dev](https://github.com/ripienaar/free-for-dev):

| Option | Free resources | Problem for TRACE |
|---|---|---|
| Vercel (current) | Serverless functions | No background jobs, so scans return 503 |
| Render, Koyeb, Northflank, most PaaS | 512 MB RAM | Semgrep and Trivy need about 2 GB, and the instance sleeps |
| Google Cloud Run | 360k GB-s per month | CPU is throttled after the response, so in-process jobs stall |
| **Oracle Cloud Always Free** | **Arm A1, 2 OCPU / 12 GB, 200 GB disk, 10 TB egress** | Needs a card for identity checks (not charged). Idle VMs can be reclaimed. |

## 1. Create the VM

1. Sign up at <https://www.oracle.com/cloud/free/>. Pick a home region with A1 capacity; you cannot change it later.
2. Go to **Compute → Instances → Create instance**:
   - Image: **Canonical Ubuntu 24.04** (aarch64).
   - Shape: **VM.Standard.A1.Flex**, 2 OCPU, 12 GB.
   - Upload your SSH public key.
   - If the region reports "Out of capacity", try another availability domain or retry later.
3. Go to **Networking → Virtual cloud networks → (your VCN) → Security Lists → Default**. Add ingress rules from `0.0.0.0/0` for TCP 80 and TCP 443.
4. Create a DNS **A record** `api.trace-psi.me` pointing to the VM's public IP.

## 2. Install and start

```bash
ssh ubuntu@<public-ip>
curl -fsSL https://raw.githubusercontent.com/atique-ahmad-01/trace/main/deploy/oracle/setup.sh | bash
cd ~/trace/deploy/oracle
cp .env.example .env && nano .env    # DATABASE_URL, SECRET_KEY, JWT_SECRET_KEY, DEMO_ADMIN_PASSWORD
sudo docker compose up -d --build
curl https://api.trace-psi.me/health
```

The first build takes several minutes because it downloads the scanner binaries and Semgrep. Use the same `DATABASE_URL`, `SECRET_KEY` and `JWT_SECRET_KEY` as the Vercel project, so existing accounts and stored credentials keep working.

## 3. Point the frontend at it

- **Vercel (frontend project):** set `NEXT_PUBLIC_API_URL=https://api.trace-psi.me` and redeploy.
- **GitHub → Settings → Variables → Actions:** set `API_URL=https://api.trace-psi.me` for the keep-alive workflow.

## Updating

```bash
cd ~/trace && git pull && cd deploy/oracle && sudo docker compose up -d --build
```

## Notes

- **Idle reclamation:** Oracle may reclaim an Always Free VM if CPU, network and memory all stay very low for 7 days. Regular scans and the keep-alive ping help. Upgrading the account to Pay As You Go removes reclamation, and Always Free resources stay free.
- **Jobs:** jobs run in-process. A restart marks running scans as failed so they can be re-run. To use queued jobs instead, add Redis and an RQ worker as in the root `docker-compose.yml`.
- **Models:** there is no Ollama on the VM by default. Each organization connects Anthropic or an OpenAI-compatible model in **Settings → Integrations**. 12 GB is enough to add the `ollama` service from the root compose file with a small model, but it will be slow on CPU.
