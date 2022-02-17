cd /d "E:\原神\PassDriver\PassDriver" &msbuild "PassDriver.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform="x64" /p:SolutionDir="E:\原神\PassDriver" 
exit %errorlevel% 