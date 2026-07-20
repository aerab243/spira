#!/bin/bash
# Script de build pour Spira
set -e

echo "🔬 Spira — Build"
echo "=================="
echo ""

# Build release
echo "📦 Build release..."
cargo build --release

echo ""
echo "✅ Build terminé !"
echo "   Binaire : target/release/spira-gui"
echo ""
echo "Pour lancer : ./target/release/spira-gui"
