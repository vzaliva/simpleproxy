Simpleproxy
===========

Original authors:
-----------------
  * Vadim Zaliva <lord@crocodile.org>
 *  Vlad Karpinsky <vlad@noir.crocodile.org>
  * Vadim Tymchenko <verylong@noir.crocodile.org>

Contributors:
-------------
  * Renzo Davoli <renzo@cs.unibo.it> (HTML probe & HTTP authentication)
  * patch submitters via sourceforge and github project pages


Description
-----------

Simpleproxy is a simple TCP proxy. It accepts connections on a local
TCP port and forward them to anoter port on a remote host via TCP.

It could be used as standalone daemon, or run via `inetd`.

For various options such as POP3 user screening, logging, HTTP proxy
support, see man page (man simpleproxy).
        

Installation
------------

To install run `./configure`. Then, do 'make install'.

License
-------

GPLv2. See LICENSE.txt for details.

Home page
---------
To report bugs and get most recent version please go to:

https://github.com/vzaliva/simpleproxy






