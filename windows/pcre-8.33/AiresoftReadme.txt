* Pcre-8.20 for Windows *
========================

What is it?
-----------
Pcre: Perl-compatible regular-expression library

Description
-----------
The PCRE library is a set of functions that implement regular expression pattern matching using the same syntax and semantics as Perl 5. PCRE has its own native API, as well as a set of wrapper functions that correspond to the POSIX regular expression API. The PCRE library is free, even for building commercial software.
	 
Homepage
--------
http://www.pcre.org
	 
System
------
- Win32, i.e. MS-Windows 95 / 98 / ME / NT / 2000 / XP / 2003 with msvcrt.dll
- if msvcrt.dll is not in your Windows/System folder, get it from
  Microsoft <http://support.microsoft.com/default.aspx?scid=kb;en-us;259403">
  or by installing Internet Explorer 4.0 or higher
  <http://www.microsoft.com/windows/ie> 

Sources
-------
- pcre-8.33-src.zip
- The source code used can be found under the ./src directory

Compilation
-----------
The package has been compiled with Visual Studio 2008. The binary files
in the bin directory have been compiled so that no part of Visual Studio
2008 or its redistributables are required for them to be used.

The VS2008 sln file used to build the components is in the 
./src/build/vc2008/ directory. This distribution of PCRE is built
with SUPPORT_JIT and SUPPORT_UTF both enabled. Also, all three
'bitness' variants (the 8, 16, and 32-bit libraries) have been 
compiled into pcre3.dll. If you desire different options, amend the
config.h file in the abovementioned directory and rebuild.

Library files
-------------
The library files required to link to the prebuilt dlls can be found 
under the ./lib directory. While these files are in Microsoft's 
library format, MinGW and gcc-alikes can consume them.

Includes
--------
The include files are under the inc directory. All functions are built
with a cdecl calling convention, including the DllGetVersion functions
in each component.