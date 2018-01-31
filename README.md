# Esquilo Secure Tunneling Protocol (ESTP) Daemon

This software implements the server side of the ESTP tunnel used in the Esquilo Air IoT prototyping board to connect the nest.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Estpd is designed to run on a Linux system.  To build estpd, you need to have basic development tools like gcc and make installed.  In addition, make sure the following packages are installed:

 * autoconf
 * openssl
 * pthreads

### Installing

To configure esptd to build, run these commands:

```
./bootstrap
./configure
```

These only need to be run once.  To then build estpd, run make:

```
make
```

## Deployment

To install estpd, you can run the install make target:

```
make install
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

