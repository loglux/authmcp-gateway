#!/bin/bash
# Deploy Wiki pages to GitHub
#
# USAGE:
#   1. Create first wiki page on GitHub (any content)
#      https://github.com/loglux/authmcp-gateway/wiki
#   2. Run: ./scripts/deploy-wiki.sh deploy
#
# This script will:
#   - Clone wiki repository (authmcp-gateway.wiki)
#   - Copy templates from docs/internal/wiki-templates/
#   - Commit and push to GitHub Wiki
#
# After deployment, edit wiki via Git:
#   git clone https://github.com/loglux/authmcp-gateway.wiki.git
#   cd authmcp-gateway.wiki
#   # Edit .md files
#   git commit -am "Update wiki"
#   git push
#
# Without arguments, shows instructions only

set -e

WIKI_TEMPLATES_DIR="docs/internal/wiki-templates"
WIKI_REPO="authmcp-gateway.wiki"

echo "📚 Deploying GitHub Wiki..."

# Check if wiki templates exist
if [ ! -d "$WIKI_TEMPLATES_DIR" ]; then
    echo "❌ Error: Wiki templates not found at $WIKI_TEMPLATES_DIR"
    exit 1
fi

# Instructions
cat << 'EOF'

=== GitHub Wiki Deployment ===

STEP 1: Create initial Wiki page (if not exists)
   1. Go to: https://github.com/loglux/authmcp-gateway/wiki
   2. Click "Create the first page"
   3. Add any title and content (will be replaced)
   4. Click "Save Page"

STEP 2: Clone Wiki repository
   Run this command:
   
   git clone https://github.com/loglux/authmcp-gateway.wiki.git

STEP 3: Copy Wiki templates and push
   
   cd authmcp-gateway.wiki
   cp -r ../docs/internal/wiki-templates/* .
   git add .
   git commit -m "📚 Add Wiki documentation"
   git push

Done! Wiki will be live at:
https://github.com/loglux/authmcp-gateway/wiki

=== Alternative: Automatic deployment ===

Run this script with 'deploy' argument after completing STEP 1:

   ./scripts/deploy-wiki.sh deploy

EOF

# If 'deploy' argument provided, do automatic deployment
if [ "$1" = "deploy" ]; then
    echo ""
    echo "🚀 Starting automatic deployment..."
    
    # Check if wiki repo exists
    if [ -d "$WIKI_REPO" ]; then
        echo "📂 Wiki repository already exists, pulling latest..."
        cd "$WIKI_REPO"
        git pull
        cd ..
    else
        echo "📥 Cloning Wiki repository..."
        git clone "https://github.com/loglux/$WIKI_REPO.git"
    fi
    
    # Copy templates
    echo "📝 Copying Wiki templates..."
    cp "$WIKI_TEMPLATES_DIR"/*.md "$WIKI_REPO/"
    
    # Commit and push
    cd "$WIKI_REPO"
    
    # Set correct git email for wiki commits
    git config user.email "37578325+loglux@users.noreply.github.com"
    
    git add .
    
    if git diff --cached --quiet; then
        echo "✅ No changes to commit"
    else
        echo "💾 Committing changes..."
        git commit -m "📚 Update Wiki documentation

Updated from docs/internal/wiki-templates/
- Home page with navigation
- FAQ with common questions
- Links to main documentation"
        
        echo "🚀 Pushing to GitHub..."
        git push
        
        echo ""
        echo "✅ Wiki deployed successfully!"
        echo "   View at: https://github.com/loglux/authmcp-gateway/wiki"
    fi
    
    cd ..
fi
