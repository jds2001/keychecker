Name:           keychecker
Version:        1.0
Release:        1%{?dist}
Summary:        Generate list of installed packages sorted by GPG key

Group:          Applications/System
License:        GPLv2+
URL:            https://fedorahosted.org/keychecker
Source0:        https://fedorahosted.org/released/%{name}/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
%if 0%{rhel} <=6
Requires:      python-argparse
%endif

%description
Separately list rpm's based on the GPG key they were signed with

%prep
%setup -q


%build

%install
rm -rf $RPM_BUILD_ROOT
install -Dpm 0755 key_checker.py $RPM_BUILD_ROOT%{_bindir}/keychecker

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/keychecker
%doc README LICENSE known_keys.txt

%changelog
* Sun Jun 11 2017 Jon Stanley <jonstanley@gmail.com> - 1.0-1
- Python 3 compatibility (carlgeorge)
- Migrate to argparse
- Various minor cleanups

* Sun Aug 16 2009 Jon Stanley <jonstanley@gmail.com> - 0.2-1
- Add option for getting keys from a file

* Tue Jul 28 2009 Jon Stanley <jonstanley@gmail.com> - 0.1-3
- Fix spec typo

* Sun Jul 26 2009 Jon Stanley <jonstanley@gmail.com> - 0.1-2
- Review fixup (combine install lines)

* Sun Jul 26 2009 Jon Stanley <jonstanley@gmail.com> - 0.1-1
- Initial package
