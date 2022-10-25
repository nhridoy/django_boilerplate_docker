#!/bin/bash
echo "#!/bin/sh
isort ./src --gitignore --profile black
black ./src
git add -A" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
