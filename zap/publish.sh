#!/bin/sh
set -eu
: "${KINESIS_STREAM_NAME:?set KINESIS_STREAM_NAME to Terraform stream_name}"
: "${AWS_REGION:?set AWS_REGION}"
while :; do
  for event in /events/*.json; do
    [ -f "$event" ] || continue
    if aws kinesis put-record --stream-name "$KINESIS_STREAM_NAME" \
      --partition-key demo-portal --data "fileb://$event" \
      --region "$AWS_REGION" --no-cli-pager; then
      rm -- "$event"
    else
      echo 'Publish failed; saved event retained for retry.' >&2
      break
    fi
  done
  sleep 10
done