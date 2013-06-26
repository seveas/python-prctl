Name:           python-prctl
Version:        1.5.0
Release:	1
Summary:        Python interface to prctl system library

Group:          System Environment/Libraries
License:        GPL
# this URL is a fork from http://github.com/seveas/python-prctl
# that ported to RHEL5 and python2.6
URL:            http://github.com/sfried/python-prctl
Source0:        %{name}-master.zip
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  python26
Requires:	python26

%description
The linux prctl function allows you to control specific characteristics of a
process' behaviour. Usage of the function is fairly messy though, due to
limitations in C and linux. This module provides a nice non-messy python(ic)
interface.

Besides prctl, this library also wraps libcap for complete capability handling
and allows you to set the process name as seen in ps and top.

See docs/index.rst for the documentation. An HTML version can be found on
http://packages.python.org/python-prctl/

%prep
%setup -q -n python-prctl-master

%build
python2.6 setup.py build

%install
rm -rf $RPM_BUILD_ROOT

install -d -m 755 $RPM_BUILD_ROOT/usr/lib64/python2.6/site-packages

#Install library
install -m 755 build/lib.linux-x86_64-2.6/*.{py*,so} $RPM_BUILD_ROOT/usr/lib64/python2.6/site-packages

cat > $RPM_BUILD_ROOT/usr/lib64/python2.6/site-packages/%{name}-%version}-py2.6.egg-info << "EOF"
Metadata-Version: 1.0
Name: python-prctl
Version: 1.5.0
Summary: Python(ic) interface to the linux prctl syscall
Home-page: http://github.com/seveas/python-prctl
Author: Dennis Kaarsemaker
Author-email: dennis@kaarsemaker.net
License: UNKNOWN
Description: UNKNOWN
Platform: UNKNOWN
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Classifier: License :: OSI Approved :: GNU General Public License (GPL)
Classifier: Operating System :: POSIX :: Linux
Classifier: Programming Language :: C
Classifier: Programming Language :: Python
Classifier: Topic :: Security
EOF

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%attr(644,-,-) /usr/lib64/python2.6/site-packages/prctl.py*
%attr(755,-,-) /usr/lib64/python2.6/site-packages/_prctl.so
%attr(400,-,-) /usr/lib64/python2.6/site-packages/*egg-info

