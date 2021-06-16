# DLL-Injection
C# program that takes process name and path to DLL payload to perform DLL injection method. Please note the program targets .NET framework 4.6.1 and was compiled using Visual Studio 2017 Community.  

Make sure if you using launcher you have file 'DllInjection.dll' in same directory with launcher executeable!

Usage (exe): InjectorLauncher.exe <Process name without .exe> <Path to DLL>  
Example (exe): InjectorLauncher.exe csgo .\super_mega_cheats_for_csgo.dll

Usage (DLL):  
  \- DllInjection.Injector.inject(string process_name, string path_to_dll, bool silent);  
Example (DLL):  
  \- using DllInjection;  
  \- Injector.inject("firefox", "mod.dll", true);
