"""Production entrypoint that mounts read-only live FlowSense data routes."""
from fastapi import Depends

from app.main import app, require_api_key, require_talq_headers
from app.flowsense_data import router as flowsense_data_router

# Every live-data endpoint requires a valid, unexpired, non-revoked client key
# and the TALQ version + clientAddress checks already enforced by the gateway.
app.include_router(
    flowsense_data_router,
    dependencies=[Depends(require_api_key), Depends(require_talq_headers)],
)
