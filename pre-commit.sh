#!/bin/bash
echo "#!/bin/sh
isort ./src --gitignore
black ./src" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
