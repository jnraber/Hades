A reverse engineer trying to understand a protected binary is faced with avoiding detection by anti-debugging protections.  Advanced protection systems may even load specialized drivers that can re-flash firmware and change the privileges of running applications, significantly increasing the penalty of detection.  Hades is a Windows kernel driver designed to aid reverse engineering endeavors.  It avoids detection by employing intelligent instrumentation via instruction rerouting in both user and kernel space.  This technique allows a reverse engineer to easily debug and profile binaries without fear of invoking protection penalties

To Build
========

1. > build -gceZw
2. Make sure that the path is C:\WinDDK\xxxx.xxxx\src\HADES
   There are dependencies in the make files.  Just easier
   to have Hades located here.

License
=======

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
