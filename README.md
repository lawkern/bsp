Big Shitty Platform
=====
A web application written in (mostly) C99.

Dependencies
-----
- fcgi

Build
-----
To build on Linux, switch to the code directory and run:

```
make
```

This will recompile the entire project (using clang) as a development build and
restart the application (using spawn-fcgi) on the port specified by
`APPLICATION_PORT` in the Makefile. To compile an optimized build, instead run:

```
make production
```

By default, the executable and data assets are deployed to the directory
`/srv/bsp`. This can be configured by updating `DEPLOYMENT_PATH` in the
Makefile. A sample server entry for nginx is provided in the misc directory.
