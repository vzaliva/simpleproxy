Name: simpleproxy
Summary: Simple TCP/IP proxy.
Packager: Vlad Karpinsky <vlad@noir.crocodile.org>
Url: https://github.com/vzaliva/simpleproxy
Version: 3.5
Release: 1
Copyright: Vadim Zaliva <lord@crocodile.org>, Vlad Karpinsky <vlad@noir.crocodile.org>, Vadim Tymchenko <verylong@noir.crocodile.org>
Group: Daemons
Source: simpleproxy-3.5.tar.gz
BuildRoot: /tmp/simpleproxy

%description
Simple TCP/IP proxy. Also provides simple POP3 pre-auth.
Can use HTTPs proxy to traverse firewalls.

%prep
rm -rf $RPM_BUILD_ROOT
%setup 

%build
./configure --prefix=$RPM_BUILD_ROOT/usr
make

%install
make install

%files
%defattr(-,root,root)
/usr/bin/simpleproxy
/usr/man/man1/simpleproxy.1.gz
%doc README.txt pop3users.txt ChangeLog

