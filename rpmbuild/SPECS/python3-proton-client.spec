%define unmangled_name proton-client
%define version 0.1.0
%define release 1

Summary: Proton Technologies API wrapper
Name: python3-proton-client
Version: %{version}
Release: %{release}
Source0: %{unmangled_name}-%{version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Proton Technologies AG <contact@protonmail.com>
Url: https://github.com/ProtonMail/proton-python-client
Requires: python3-requests
Requires: python3-pyOpenSSL
Requires: python3-bcrypt
Requires: python3-gnupg

%{?python_disable_dependency_generator}

%description
This package, originally forked from python-srp module implements a simple
wrapper to the Proton Technologies API, abstracting from the SRP authentication.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
