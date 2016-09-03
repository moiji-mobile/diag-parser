diag-parser
===========
[![Build Status](https://travis-ci.org/moiji-mobile/diag-parser.svg?branch=master)](https://travis-ci.org/moiji-mobile/diag-parser)

Parse the Qualcomm DIAG format and convert 2G, 3G and 4G radio messages to
Osmocom GSMTAP for analysis in wireshark and other utilities.

Building and Using
------------------

Building on GNU/Linux with autoconf, automake, make, gcc, libtalloc, libtool
already installed.

```
$ ./build/build_local.sh
# Use -i to configure logging using DIAG and write to net+file
$ ./diag_import -g A.B.C.D -p local_file.pcap -i /dev/ttyUSB0
# Use an existing diag file
$ ./diag_import -g A.B.C.D -p local_file.pcap trace.bin
```


Devices
-------

Development is done using [Quectel UC20](http://amzn.to/2bJ26Es) and
[Quectel EC20](http://amzn.to/2bQOYZI) modems inside a PCengine APU2
system.


License
-------

Copyright (C) 2016 Holger Hans Peter Freyther

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

See COPYING for details.

Based on the gsmparser release by SR labs
