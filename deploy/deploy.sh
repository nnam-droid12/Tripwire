#!/usr/bin/env bash
# Deploy the Tripwire backend + family dashboard to Cloud Run.
#
#   bash deploy/deploy.sh            # PROJECT / REGION can be overridden by env
#
# Idempotent: re-running updates secrets and redeploys. Secret values are read
# from .env and piped to Secret Manager; they are never printed or baked into
# the image. Requires the gcloud CLI, logged in with access to the project,
# and the project's Python venv (for reading .env).
set -euo pipefail

PROJECT="${PROJECT:-nixora-project}"
REGION="${REGION:-us-east1}"  # same region as the other services in the project
SERVICE="tripwire"
BUCKET="${PROJECT}-tripwire-incidents"
SA="tripwire-backend@${PROJECT}.iam.gserviceaccount.com"
PY="${PY:-.venv/Scripts/python}"
G="gcloud --project=${PROJECT} --quiet"

env_value() {  # read KEY from .env without echoing it
  "$PY" -c 'import sys; from dotenv import dotenv_values; print(dotenv_values(".env").get(sys.argv[1]) or "", end="")' "$1"
}

echo "== APIs"
$G services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com storage.googleapis.com iam.googleapis.com

echo "== Service account (least privilege)"
$G iam service-accounts describe "$SA" >/dev/null 2>&1 || \
  $G iam service-accounts create tripwire-backend --display-name="Tripwire backend (Cloud Run)"

# lets the service call Text-to-Speech (Margaret's and Tripwire's voices) billed to this project
$G projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA}" \
  --role=roles/serviceusage.serviceUsageConsumer --condition=None >/dev/null

echo "== Private incident bucket, objects deleted after 30 days"
if ! $G storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1; then
  $G storage buckets create "gs://${BUCKET}" --location="$REGION" --uniform-bucket-level-access --public-access-prevention
fi
LIFECYCLE="$(mktemp)"
echo '{"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]}' > "$LIFECYCLE"
$G storage buckets update "gs://${BUCKET}" --lifecycle-file="$LIFECYCLE" >/dev/null
$G storage buckets add-iam-policy-binding "gs://${BUCKET}" --member="serviceAccount:${SA}" --role=roles/storage.objectAdmin >/dev/null

echo "== Secrets"
put_secret() {  # name, value (empty value: skip)
  local name="$1" value="$2"
  if [ -z "$value" ]; then echo "   skip $name (no value in .env)"; return; fi
  if $G secrets describe "$name" >/dev/null 2>&1; then
    printf '%s' "$value" | $G secrets versions add "$name" --data-file=- >/dev/null
  else
    printf '%s' "$value" | $G secrets create "$name" --replication-policy=automatic --data-file=- >/dev/null
  fi
  $G secrets add-iam-policy-binding "$name" --member="serviceAccount:${SA}" --role=roles/secretmanager.secretAccessor >/dev/null
  echo "   set $name"
}
put_secret tripwire-agent-token "$(env_value TRIPWIRE_AGENT_TOKEN)"
put_secret tripwire-dashboard-key "$(env_value TRIPWIRE_DASHBOARD_KEY)"
put_secret tripwire-meta-api-key "$(env_value META_API_KEY)"
put_secret tripwire-baseten-api-key "$(env_value BASETEN_API_KEY)"
put_secret tripwire-twilio-sid "$(env_value TWILIO_ACCOUNT_SID)"
put_secret tripwire-twilio-token "$(env_value TWILIO_AUTH_TOKEN)"
put_secret tripwire-twilio-from "$(env_value TWILIO_FROM_NUMBER)"
put_secret tripwire-family-phone "$(env_value FAMILY_PHONE_NUMBER)"

SECRETS="TRIPWIRE_AGENT_TOKEN=tripwire-agent-token:latest,TRIPWIRE_DASHBOARD_KEY=tripwire-dashboard-key:latest,META_API_KEY=tripwire-meta-api-key:latest,BASETEN_API_KEY=tripwire-baseten-api-key:latest"
for pair in TWILIO_ACCOUNT_SID=tripwire-twilio-sid TWILIO_AUTH_TOKEN=tripwire-twilio-token TWILIO_FROM_NUMBER=tripwire-twilio-from FAMILY_PHONE_NUMBER=tripwire-family-phone; do
  if $G secrets describe "${pair#*=}" >/dev/null 2>&1; then SECRETS="${SECRETS},${pair}:latest"; fi
done

echo "== Deploy"
URL="$($G run services describe "$SERVICE" --region="$REGION" --format='value(status.url)' 2>/dev/null || true)"
$G run deploy "$SERVICE" --source=. --region="$REGION" --service-account="$SA" \
  --allow-unauthenticated --max-instances=1 --memory=1Gi --cpu=2 --no-cpu-throttling --timeout=3600 \
  --set-env-vars="TRIPWIRE_GCS_BUCKET=${BUCKET},META_BASE_URL=https://api.meta.ai/v1,META_MODEL=muse-spark-1.3,META_REASONING_EFFORT=low,BASETEN_BASE_URL=https://inference.baseten.co/v1,BASETEN_MODEL=meta-models/muse-spark-open-1026,BASETEN_REASONING_EFFORT=low,TRIPWIRE_PUBLIC_DASHBOARD=${PUBLIC_DASHBOARD:-1},TRIPWIRE_GCP_PROJECT=${PROJECT},TRIPWIRE_PUBLIC_URL=${URL:-https://pending}" \
  --set-secrets="$SECRETS"
URL="$($G run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')"
$G run services update "$SERVICE" --region="$REGION" --update-env-vars="TRIPWIRE_PUBLIC_URL=${URL}" >/dev/null

echo "== Done: ${URL}"
echo "Set TRIPWIRE_BACKEND_URL=${URL} in .env so the agent reports to the cloud."
