              NRL SMF Source Code Distribution

The NRL Simplified Multicast Forwarding (nrlsmf) project
includes software for a user-space forwarding engine.  This
software is was developed by the Naval Research Laboratory
(NRL) PROTocol Engineering Advanced Networking (PROTEAN)
Research Group.  The goal of this effort is to provide an
implementation of experimental techniques for robust,
efficient distribution of broadcast or multicast packets in
dynamic, wireless networks such as Mobile Ad-hoc Networks
(MANETs).  

The nrlsmf application can be run as a stand-alone
application capable of providing  "classic" flooding of
broadcast and multicast traffic for a specified network
interface or can be used in conjunction with a controlling
program to perform more sophisticated multicast forwarding. 
An interprocess communication "remote control" interface is
provided so that a compatible program (e.g. nrlolsr) may issue
real-time commands to nrlsmf to control the multicast
forwarding process.  Both IPv4 and IPv6 operation are
supported.  Versions of nrlsmf can be built for the following
operating systems:  Linux, MacOS, BSD, Win32, and WinCE. 

Build Instructions 

For Unix platforms, the "smf/unix" directory in the source
tree contains Makefiles for different platforms.  Type:

make Makefile.<ostype> nrlsmf 

to build the nrlsmf binary executable.   

For Win32 platforms (TBD), a distribution of "winpcap" is
required to build the nrlsmf.exe executable.  A Visual C++
workspace (nrlsmf.dsw) and project files are provided in
the "smf/win32" directory for building nrlsmf.exe. 

For WinCE (a.k.a. PocketPC) platforms, the "RawEther"
library is required.  The Rawether development kit is a
commercial product available from http://www.rawether.net. 
(Note we are able to provide a binary distribution of
nrlsmf.exe for WinCE platforms including the required
Rawether libraries).  A workspace (nrlsmf.vcw) and project
files are provided for the Embedded Visual C++ compiler.

See the "nrlsmf.html" or "nrlsmf.pdf" file for further
instructions.  These files will be updated soon to have
the "User's Guide" for the new "nrlsmf" code.
