%define unmangled_name proton-client
%define version 0.7.1
%define release 3

Prefix: %{_prefix}

Name: python3-proton-client
Version: %{version}
Release: %{release}
Summary: Safely login with ProtonVPN credentials to connect to Proton.

Group: ProtonVPN
License: GPLv3
Url: https://github.com/ProtonMail/proton-python-client
Vendor: Proton Technologies AG <contact@protonmail.com>
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-devel
BuildRequires: python3-setuptools
Requires: python3-requests
Requires: python3-pyOpenSSL
Requires: python3-bcrypt
Requires: python3-gnupg
Conflicts: python3-protonvpn-nm-lib < 3.5.0

%{?python_disable_dependency_generator}

%description
This package, originally forked from python-srp module implements a simple
wrapper to Proton Technologies API, abstracting from the SRP authentication.

%prep
%setup -q -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
%{python3} setup.py build

%install
%{python3} setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%{python3_sitelib}/proton/
%{python3_sitelib}/proton_client-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Thu Sep 22 2021 Proton Technologies AG <opensource@proton.me> 0.7.1-3
- Drop F34-35 and add F37

* Fri Sep 24 2021 Proton Technologies AG <opensource@proton.me> 0.7.1-2
- Improve: Logging
- Improve: Alternative routing logic
- Improve: Human verification logic

* Fri Sep 24 2021 Proton Technologies AG <opensource@proton.me> 0.7.0-1
- Feature: Request human verification
- Fix: Allow to make and retrieve non-json responses from API

* Thu Jul 08 2021 Proton Technologies AG <opensource@proton.me> 0.6.1-4
- Feature: Alternative Routing

* Mon May 24 2021 Proton Technologies AG <opensource@proton.me> 0.5.1-3
- Add new exceptions for improved case handling

* Fri Apr 30 2021 Proton Technologies AG <opensource@proton.me> 0.5.0-1
- Add new exceptions
- Throw custom exceptions in case of network errors, abstracting from the package that is being used for requests

* Wed Apr 21 2021 Proton Technologies AG <opensource@proton.me> 0.4.1-1
- Add long description to setup.py

* Mon Apr 19 2021 Proton Technologies AG <opensource@proton.me> 0.4.0-1
- Add proxy support
- Verify fingerprint of signer key

* Tue Jan 26 2021 Proton Technologies AG <opensource@proton.me> 0.3.0-1
- Set flags to BNs in the openssl implementation using BN_set_flags and BN_FLAG_CONSTTIME

* Tue Jan 26 2021 Proton Technologies AG <opensource@proton.me> 0.2.0-4
- Update .spec file for public release