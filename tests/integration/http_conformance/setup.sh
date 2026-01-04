#!/bin/bash
set -e

echo "[INFO] Setting up HTTP Conformance Test Suite"
echo "=============================================="

CONFORMANCE_DIR="tests/integration/http_conformance"
CONFORMANCE_REPO="https://github.com/cispa/http-conformance.git"
CONFORMANCE_CLONE_DIR="$CONFORMANCE_DIR/http-conformance"

# Check if already cloned
if [ -d "$CONFORMANCE_CLONE_DIR" ]; then
    echo "[INFO] HTTP conformance suite already exists at $CONFORMANCE_CLONE_DIR"
    echo "[INFO] Pulling latest changes..."
    cd "$CONFORMANCE_CLONE_DIR"
    git pull
    cd - > /dev/null
else
    echo "[INFO] Cloning HTTP conformance test suite..."
    git clone --recurse-submodules "$CONFORMANCE_REPO" "$CONFORMANCE_CLONE_DIR"
fi

# Create a minimal .env file (no database required for local testing)
echo "[INFO] Creating minimal .env configuration..."
cat > "$CONFORMANCE_CLONE_DIR/.env" << 'EOF'
# Minimal configuration for local testing without database
# Database connection (not required for basic local tests)
DATABASE_URL=sqlite:///conformance_results.db
EOF

echo "[INFO] Installing Python dependencies..."
cd "$CONFORMANCE_CLONE_DIR"

# Install poetry if not available
if ! command -v poetry &> /dev/null; then
    echo "[WARN] Poetry not found. Installing dependencies with pip instead..."
    pip install -e . || echo "[WARN] Package install failed, will use direct imports"
else
    echo "[INFO] Installing with poetry..."
    poetry install --no-dev
fi

echo "[SUCCESS] HTTP Conformance Test Suite setup complete!"
echo ""
echo "Next steps:"
echo "  - Run conformance tests: pixi run conformance_tests"
echo "  - Or manually: bash scripts/http_conformance_test.sh"
