#!/usr/bin/env bash
echo "###################################"
echo "#    Installing analysis tools    #"
echo "###################################"
echo "Starting APKiD installation..."
pip install --upgrade wheel
pip wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0
pip install --no-index --find-links=/tmp/yara-python yara-python
pip install apkid
echo "Done!"
cd analysis
mkdir tools
cd tools || exit 1
echo "Starting CFR installation..."
git clone https://github.com/NoahMauthe/cfr.git
cd cfr || exit 1
mvn package
echo "Done!"
cd ..
echo "Starting Procyon installation..."
git clone https://github.com/NoahMauthe/procyon.git
cd procyon || exit 1
./gradlew wrapper --gradle-version=4.10.3
./gradlew fatJar
echo "Done!"
cd ..
echo "Starting fernflower installation..."
git clone https://github.com/fesh0r/fernflower.git
cd fernflower || exit 1
./gradlew jar
echo "Done!"
cd ..
echo "Starting jadx installation..."
git clone https://github.com/skylot/jadx.git
cd jadx || exit 1
./gradlew dist
echo "Done!"
cd ..
echo "Starting dex2jar installation..."
git clone https://github.com/pxb1988/dex2jar.git
cd dex2jar || exit 1
./gradlew build
cd dex-tools/build/distributions || exit 1
unzip dex-tools-2.1-SNAPSHOT.zip
cd ../../../
echo "Done!"
cd ../../
echo "#################################"
echo "# Finished building decompilers #"
echo "#################################"
