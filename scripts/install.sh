#!/bin/bash
# Script d'installation pour Spira sur Ubuntu
set -e

echo "🔬 Installation de Spira"
echo "========================"
echo ""

# Vérifier si Rust est installé
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust n'est pas installé."
    echo "   Installez-le avec : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "✅ Rust détecté : $(cargo --version)"
echo ""

# Build
echo "📦 Compilation de Spira..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Échec de la compilation"
    exit 1
fi

echo ""
echo "✅ Spira est installé !"
echo ""
echo "Pour lancer Spira :"
echo "   ./target/release/spira-gui"
echo ""
echo "Pour lancer depuis n'importe où :"
echo "   sudo cp target/release/spira-gui /usr/local/bin/spira"
echo "   spira"
