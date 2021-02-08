# Setup 
rm -rf tools 
mkdir tools
cd tools 

wget https://github.com/Konloch/bytecode-viewer/releases/download/v2.9.22/Bytecode-Viewer-2.9.22.jar
wget https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.jar
wget https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar

wget https://download.jetbrains.com/resharper/dotUltimate.2020.3.2/JetBrains.dotPeek.2020.3.2.web.exe
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v5.0-rc2/ILSpy-linux-x64-Release.zip
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v5.0-rc2/ILSpy-osx-x64-Release.zip
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v5.0-rc2/ILSpy-win-x64-Release.zip

wget https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win32.zip
wget https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win64.zip
wget https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-netframework.zip

wget https://github.com/icsharpcode/ILSpy/releases/download/v6.2.1/ILSpy_binaries_6.2.1.6137.zip

git clone https://github.com/ayomawdb/jd-core-java.git
cd jd-core-java
git fetch
git checkout patch-1
./gradlew assemble
cd ..
cp jd-core-java/build/libs/*.jar .
rm -rf jd-core-java
