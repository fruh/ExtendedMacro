#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

date
[ -e build ] || mkdir -v build
[ -e dist ] || mkdir -v dist
cd src/
javac -Xlint:unchecked -d ../build/ burp/BurpExtender.java

cd ../build/
jar -cf ../dist/extendedmacro.jar burp/*.class

echo "Output: ${DIR}/dist/extendedmacro.jar"
