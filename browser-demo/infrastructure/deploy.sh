#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Verify terraform is available
if ! command -v terraform &> /dev/null; then
  echo "Error: terraform not found in PATH"
  exit 1
fi

# Verify infrastructure exists
if [ ! -f terraform.tfstate ]; then
  echo "Error: terraform.tfstate not found. Run 'terraform apply' first."
  exit 1
fi

# Build browser demo
echo "Building browser demo..."
cd ..
npm install --silent
npm run build

# Get deployment config
cd infrastructure
BUCKET_NAME=$(terraform output -raw bucket_name)
DISTRIBUTION_ID=$(terraform output -raw cloudfront_distribution_id)
WEBSITE_URL=$(terraform output -raw website_url)

# Upload to S3 (assets with long cache, HTML with short cache)
echo "Uploading to S3 ($BUCKET_NAME)..."
aws s3 sync ../dist/ "s3://${BUCKET_NAME}" \
  --delete \
  --cache-control "public, max-age=86400" \
  --exclude "*.html" \
  --quiet

aws s3 sync ../dist/ "s3://${BUCKET_NAME}" \
  --cache-control "public, max-age=0, must-revalidate" \
  --exclude "*" \
  --include "*.html" \
  --quiet

# Invalidate CloudFront cache
echo "Invalidating CloudFront ($DISTRIBUTION_ID)..."
aws cloudfront create-invalidation \
  --distribution-id "${DISTRIBUTION_ID}" \
  --paths "/*" \
  --query 'Invalidation.Id' \
  --output text > /dev/null

echo "Deployed to ${WEBSITE_URL}"
