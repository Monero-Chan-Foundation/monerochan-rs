#!/bin/bash
# Script to publish all monerochan crates to crates.io in dependency order
# Usage: ./publish-all.sh [--dry-run]

# Don't exit on error - we handle errors manually
set +e

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "🔍 DRY RUN MODE - No crates will actually be published"
fi

# Crates in dependency order (dependencies first, then dependents)
# Excludes: test-artifacts, perf (have publish = false)
CRATES=(
    # "crates/primitives"
    # "crates/curves"
    # "crates/derive"
    # "crates/helper"
    "crates/build"
    "crates/core/executor"
    "crates/core/machine"
    "crates/stark"
    "crates/recursion/derive"
    "crates/recursion/core"
    "crates/recursion/compiler"
    "crates/recursion/circuit"
    "crates/recursion/gnark-cli"
    "crates/recursion/gnark-ffi"
    "crates/prover"
    "crates/cuda"
    "crates/verifier"
    "crates/zkvm/lib"
    "crates/zkvm/entrypoint"
    "crates/cli"
    "crates/sdk"
)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SUCCESS=0
FAILED=0
SKIPPED=0

echo "📦 Publishing MoneroChan crates to crates.io"
echo "=============================================="
echo ""

for crate_path in "${CRATES[@]}"; do
    crate_name=$(basename "$crate_path")
    crate_dir="$ROOT_DIR/$crate_path"
    
    if [[ ! -d "$crate_dir" ]]; then
        echo -e "${YELLOW}⚠️  Skipping $crate_name: directory not found${NC}"
        ((SKIPPED++))
        continue
    fi
    
    cd "$crate_dir"
    
    # Check if crate has publish = false
    if grep -q "^publish\s*=\s*false" Cargo.toml 2>/dev/null; then
        echo -e "${YELLOW}⏭️  Skipping $crate_name: publish = false${NC}"
        ((SKIPPED++))
        continue
    fi
    
    echo -e "${GREEN}📤 Publishing $crate_name...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        PUBLISH_OUTPUT=$(cargo publish --dry-run 2>&1 | tee /tmp/publish-$crate_name-dry.log)
        PUBLISH_EXIT=$?
        
        if echo "$PUBLISH_OUTPUT" | grep -qE "(Uploading|Published|aborting upload due to dry run|Finished.*target|already uploaded|already exists)"; then
            if echo "$PUBLISH_OUTPUT" | grep -qiE "(already uploaded|already exists)"; then
                echo -e "${YELLOW}   ⚠️  Already published (skipping)${NC}"
                ((SKIPPED++))
            else
                echo -e "${GREEN}   ✓ Dry run successful${NC}"
                ((SUCCESS++))
            fi
        elif [[ $PUBLISH_EXIT -eq 0 ]]; then
            echo -e "${GREEN}   ✓ Dry run successful${NC}"
            ((SUCCESS++))
        else
            echo -e "${RED}   ✗ Dry run failed (exit code: $PUBLISH_EXIT)${NC}"
            ((FAILED++))
        fi
    else
        # Actually publish
        PUBLISH_OUTPUT=$(cargo publish 2>&1 | tee /tmp/publish-$crate_name.log)
        PUBLISH_EXIT=$?
        
        if echo "$PUBLISH_OUTPUT" | grep -qE "(Published|Uploaded)"; then
            echo -e "${GREEN}   ✓ Successfully published $crate_name${NC}"
            ((SUCCESS++))
            # Wait a few seconds to avoid rate limits (crates.io doesn't have strict limits, but be nice)
            echo "   ⏳ Waiting 3 seconds before next publish..."
            sleep 3
        elif echo "$PUBLISH_OUTPUT" | grep -qiE "(already uploaded|already exists)"; then
            echo -e "${YELLOW}   ⚠️  Already published (skipping)${NC}"
            ((SKIPPED++))
        else
            echo -e "${RED}   ✗ Failed to publish $crate_name (exit code: $PUBLISH_EXIT)${NC}"
            echo "   Check /tmp/publish-$crate_name.log for details"
            ((FAILED++))
            # Ask if user wants to continue
            read -p "   Continue with remaining crates? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Aborting..."
                break
            fi
        fi
    fi
    
    echo ""
done

cd "$ROOT_DIR"

echo "=============================================="
echo -e "${GREEN}✓ Successfully published: $SUCCESS${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}✗ Failed: $FAILED${NC}"
fi
if [[ $SKIPPED -gt 0 ]]; then
    echo -e "${YELLOW}⏭️  Skipped: $SKIPPED${NC}"
fi

