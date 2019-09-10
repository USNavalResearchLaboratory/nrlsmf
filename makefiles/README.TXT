TO BUILD:

Type: "make -f Makefile.<system> nrlsmf"

For example, for Linux:

"make -f Makefile.linux smurf"

Even though Makefiles for other systems are included, at the moment
I have not yet implemented the "ProtoCap" class for BSD (non MacOS and other 
BSD systems).  I plan to do this ASAP.

Brian Adamson
<mailto:adamson@itd.nrl.navy.mil>
16 MAR 2005

CORE Namespaces build notes.
Temporary fix until linux kernel is patched to avoid pid issues related to namespaces.
Use make -f Makefile.core 
this will include Makefile.corecommon

These files can be removed when new kernel issues are resolved.
