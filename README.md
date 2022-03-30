Big Shitty Platform
=====
A web application written in (mostly) C99.

Build
-----

To build on Linux, run `make` from the code directory. This will recompile the
entire project (using clang) as a development build and restart the application
(using spawn-fcgi) on the port specified by `APPLICATION_PORT` in the
Makefile. To compile an optimized build, run `make production` instead.

A sample server entry for nginx is provided in the misc directory.

Dependencies
-----
- fcgi
