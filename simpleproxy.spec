Name: simpleproxy
Summary: Simple TCP/IP proxy.
Packager: Vlad Karpinsky <vlad@crocodile.org>
Url: http://www.crocodile.org/software.html
Version: 2.3b
Release: 1
Copyright: Vadim Zaliva <lord@crocodile.org>, Vlad Karpinsky <vlad@crocodile.org> 
Group: Daemons
Source: ftp://ftp.crocodile.org/pub/simpleproxy-2.3b.tar.gz
BuildRoot: /tmp/simpleproxy

%description
Simple TCP/IP proxy. Also provides simple POP3 pre-auth.
Can use HTTPs proxy to penetrate firewalls.

%prep
rm -rf $RPM_BUILD_ROOT
%setup -n simpleproxy

%build
./configure --prefix=$RPM_BUILD_ROOT/usr
make

%install
make install

%files
%defattr(-,root,root)
/usr/bin/simpleproxy
/usr/man/man1/simpleproxy.1
%doc README pop3users.txt ChangeLog

