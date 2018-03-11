Name:           strongswan
Release:        2%{?dist}
Version:        5.6.2
Summary:        An OpenSource IPsec-based VPN and TNC solution
Group:          System Environment/Daemons
License:        GPLv2+
URL:            http://www.strongswan.org/
Source0:        http://download.strongswan.org/%{name}-%{version}.tar.bz2

Source1:        %{name}.sysvinit

BuildRequires:  gmp-devel autoconf automake
BuildRequires:  libcurl-devel
BuildRequires:  openldap-devel
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
BuildRequires:  gettext-devel
BuildRequires:  trousers-devel
BuildRequires:  libxml2-devel
BuildRequires:  pam-devel
BuildRequires:  json-c-devel
BuildRequires:  libgcrypt-devel
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts

%description
The strongSwan IPsec implementation supports both the IKEv1 and IKEv2 key
exchange protocols in conjunction with the native NETKEY IPsec stack of the
Linux kernel.

%package libipsec
Summary: Strongswan's libipsec backend
Group: System Environment/Daemons
%description libipsec
The kernel-libipsec plugin provides an IPsec backend that works entirely
in userland, using TUN devices and its own IPsec implementation libipsec.

%package tnc-imcvs
Summary: Trusted network connect (TNC)'s IMC/IMV functionality
Group: Applications/System
Requires: %{name} = %{version}
%description tnc-imcvs
This package provides Trusted Network Connect's (TNC) architecture support.
It includes support for TNC client and server (IF-TNCCS), IMC and IMV message
exchange (IF-M), interface between IMC/IMV and TNC client/server (IF-IMC
and IF-IMV). It also includes PTS based IMC/IMV for TPM based remote
attestation, SWID IMC/IMV, and OS IMC/IMV. It's IMC/IMV dynamic libraries
modules can be used by any third party TNC Client/Server implementation
possessing a standard IF-IMC/IMV interface. In addition, it implements
PT-TLS to support TNC over TLS.

%prep
%setup -q -n %{name}-%{version}%{?prerelease}

echo "For migration from 4.6 to 5.0 see http://wiki.strongswan.org/projects/strongswan/wiki/CharonPlutoIKEv1" > README.Fedora

%build
autoreconf

%configure --disable-static \
    --with-ipsec-script=%{name} \
    --sysconfdir=%{_sysconfdir}/%{name} \
    --with-ipsecdir=%{_libexecdir}/%{name} \
    --bindir=%{_libexecdir}/%{name} \
    --with-ipseclibdir=%{_libdir}/%{name} \
    --with-fips-mode=0 \
    --with-tss=trousers \
    --enable-openssl \
    --enable-unity \
    --enable-ctr \
    --enable-ccm \
    --enable-gcm \
    --enable-md4 \
    --enable-gcrypt \
    --enable-xauth-eap \
    --enable-xauth-pam \
    --enable-xauth-noauth \
    --enable-eap-md5 \
    --enable-eap-gtc \
    --enable-eap-tls \
    --enable-eap-ttls \
    --enable-eap-peap \
    --enable-eap-mschapv2 \
    --enable-farp \
    --enable-dhcp \
    --enable-sqlite \
    --enable-tnc-ifmap \
    --enable-tnc-pdp \
    --enable-imc-test \
    --enable-imv-test \
    --enable-imc-scanner \
    --enable-imv-scanner  \
    --enable-imc-attestation \
    --enable-imv-attestation \
    --enable-imv-os \
    --enable-imc-os \
    --enable-eap-tnc \
    --enable-tnccs-20 \
    --enable-tnccs-11 \
    --enable-tnccs-dynamic \
    --enable-tnc-imc \
    --enable-tnc-imv \
    --enable-eap-radius \
    --enable-curl \
    --enable-eap-identity \
    --enable-cmd \
    --enable-acert \
    --enable-aikgen \
    --enable-vici \
    --enable-swanctl \
    --enable-kernel-libipsec

make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
# prefix man pages
for i in %{buildroot}%{_mandir}/*/*; do
    if echo "$i" | grep -vq '/%{name}[^\/]*$'; then
        mv "$i" "`echo "$i" | sed -re 's|/([^/]+)$|/%{name}_\1|'`"
    fi
done
# delete unwanted library files
rm %{buildroot}%{_libdir}/%{name}/*.so
find %{buildroot} -type f -name '*.la' -delete
# fix config permissions
chmod 644 %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf
# protect configuration from ordinary user's eyes
chmod 700 %{buildroot}%{_sysconfdir}/%{name}
# Create ipsec.d directory tree.
install -d -m 700 %{buildroot}%{_sysconfdir}/%{name}/ipsec.d
for i in aacerts acerts certs cacerts crls ocspcerts private reqs; do
    install -d -m 700 %{buildroot}%{_sysconfdir}/%{name}/ipsec.d/${i}
done

install -D -m 755 %{SOURCE1} %{buildroot}/%{_initddir}/%{name}

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}

%preun
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
/sbin/ldconfig

%files
%doc README README.Fedora COPYING NEWS TODO
%config(noreplace) %{_sysconfdir}/%{name}
%{_initddir}/%{name}
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libcharon.so.0
%{_libdir}/%{name}/libcharon.so.0.0.0
%{_libdir}/%{name}/libtls.so.0
%{_libdir}/%{name}/libtls.so.0.0.0
%{_libdir}/%{name}/libpttls.so.0
%{_libdir}/%{name}/libpttls.so.0.0.0
%{_libdir}/%{name}/lib%{name}.so.0
%{_libdir}/%{name}/lib%{name}.so.0.0.0
%{_libdir}/%{name}/libvici.so.0
%{_libdir}/%{name}/libvici.so.0.0.0
%{_libdir}/%{name}/libtpmtss.so.0
%{_libdir}/%{name}/libtpmtss.so.0.0.0
%dir %{_libdir}/%{name}/plugins
%{_libdir}/%{name}/plugins/lib%{name}-aes.so
%{_libdir}/%{name}/plugins/lib%{name}-ctr.so
%{_libdir}/%{name}/plugins/lib%{name}-unity.so
%{_libdir}/%{name}/plugins/lib%{name}-ccm.so
%{_libdir}/%{name}/plugins/lib%{name}-gcm.so
%{_libdir}/%{name}/plugins/lib%{name}-gcrypt.so
%{_libdir}/%{name}/plugins/lib%{name}-attr.so
%{_libdir}/%{name}/plugins/lib%{name}-cmac.so
%{_libdir}/%{name}/plugins/lib%{name}-constraints.so
%{_libdir}/%{name}/plugins/lib%{name}-des.so
%{_libdir}/%{name}/plugins/lib%{name}-dnskey.so
%{_libdir}/%{name}/plugins/lib%{name}-fips-prf.so
%{_libdir}/%{name}/plugins/lib%{name}-gmp.so
%{_libdir}/%{name}/plugins/lib%{name}-hmac.so
%{_libdir}/%{name}/plugins/lib%{name}-kernel-netlink.so
%{_libdir}/%{name}/plugins/lib%{name}-md5.so
%{_libdir}/%{name}/plugins/lib%{name}-nonce.so
%{_libdir}/%{name}/plugins/lib%{name}-openssl.so
%{_libdir}/%{name}/plugins/lib%{name}-pem.so
%{_libdir}/%{name}/plugins/lib%{name}-pgp.so
%{_libdir}/%{name}/plugins/lib%{name}-pkcs1.so
%{_libdir}/%{name}/plugins/lib%{name}-pkcs8.so
%{_libdir}/%{name}/plugins/lib%{name}-pkcs12.so
%{_libdir}/%{name}/plugins/lib%{name}-rc2.so
%{_libdir}/%{name}/plugins/lib%{name}-sshkey.so
%{_libdir}/%{name}/plugins/lib%{name}-pubkey.so
%{_libdir}/%{name}/plugins/lib%{name}-random.so
%{_libdir}/%{name}/plugins/lib%{name}-resolve.so
%{_libdir}/%{name}/plugins/lib%{name}-revocation.so
%{_libdir}/%{name}/plugins/lib%{name}-sha1.so
%{_libdir}/%{name}/plugins/lib%{name}-sha2.so
%{_libdir}/%{name}/plugins/lib%{name}-socket-default.so
%{_libdir}/%{name}/plugins/lib%{name}-stroke.so
%{_libdir}/%{name}/plugins/lib%{name}-updown.so
%{_libdir}/%{name}/plugins/lib%{name}-x509.so
%{_libdir}/%{name}/plugins/lib%{name}-xauth-generic.so
%{_libdir}/%{name}/plugins/lib%{name}-xauth-eap.so
%{_libdir}/%{name}/plugins/lib%{name}-xauth-pam.so
%{_libdir}/%{name}/plugins/lib%{name}-xauth-noauth.so
%{_libdir}/%{name}/plugins/lib%{name}-xcbc.so
%{_libdir}/%{name}/plugins/lib%{name}-md4.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-md5.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-gtc.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-tls.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-ttls.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-peap.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-mschapv2.so
%{_libdir}/%{name}/plugins/lib%{name}-farp.so
%{_libdir}/%{name}/plugins/lib%{name}-dhcp.so
%{_libdir}/%{name}/plugins/lib%{name}-curl.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-identity.so
%{_libdir}/%{name}/plugins/lib%{name}-acert.so
%{_libdir}/%{name}/plugins/lib%{name}-vici.so
%{_libdir}/%{name}/plugins/lib%{name}-counters.so
%{_libdir}/%{name}/plugins/lib%{name}-curve25519.so
%{_libdir}/%{name}/plugins/lib%{name}-mgf1.so

%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/_copyright
%{_libexecdir}/%{name}/_updown
%{_libexecdir}/%{name}/charon
%{_libexecdir}/%{name}/scepclient
%{_libexecdir}/%{name}/starter
%{_libexecdir}/%{name}/stroke
%{_libexecdir}/%{name}/_imv_policy
%{_libexecdir}/%{name}/imv_policy_manager
%{_libexecdir}/%{name}/pki
%{_libexecdir}/%{name}/aikgen
%{_sbindir}/charon-cmd
%{_sbindir}/%{name}
%{_sbindir}/swanctl
%{_mandir}/man1/%{name}_pki*.1.gz
%{_mandir}/man1/%{name}_pt-tls-client.1.gz
%{_mandir}/man5/%{name}.conf.5.gz
%{_mandir}/man5/%{name}_ipsec.conf.5.gz
%{_mandir}/man5/%{name}_ipsec.secrets.5.gz
%{_mandir}/man5/%{name}_swanctl.conf.5.gz
%{_mandir}/man8/%{name}.8.gz
%{_mandir}/man8/%{name}_scepclient.8.gz
%{_mandir}/man8/%{name}_charon-cmd.8.gz
%{_mandir}/man8/%{name}_swanctl.8.gz
%{_datadir}/%{name}/templates/config/
%{_datadir}/%{name}/templates/database/

%files tnc-imcvs
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libimcv.so.0
%{_libdir}/%{name}/libimcv.so.0.0.0
%{_libdir}/%{name}/libtnccs.so.0
%{_libdir}/%{name}/libtnccs.so.0.0.0
%{_libdir}/%{name}/libradius.so.0
%{_libdir}/%{name}/libradius.so.0.0.0
%dir %{_libdir}/%{name}/imcvs
%{_libdir}/%{name}/imcvs/imc-attestation.so
%{_libdir}/%{name}/imcvs/imc-scanner.so
%{_libdir}/%{name}/imcvs/imc-test.so
%{_libdir}/%{name}/imcvs/imc-os.so
%{_libdir}/%{name}/imcvs/imv-attestation.so
%{_libdir}/%{name}/imcvs/imv-scanner.so
%{_libdir}/%{name}/imcvs/imv-test.so
%{_libdir}/%{name}/imcvs/imv-os.so
%dir %{_libdir}/%{name}/plugins
%{_libdir}/%{name}/plugins/lib%{name}-pkcs7.so
%{_libdir}/%{name}/plugins/lib%{name}-sqlite.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-tnc.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-radius.so
%{_libdir}/%{name}/plugins/lib%{name}-tnc-imc.so
%{_libdir}/%{name}/plugins/lib%{name}-tnc-imv.so
%{_libdir}/%{name}/plugins/lib%{name}-tnc-tnccs.so
%{_libdir}/%{name}/plugins/lib%{name}-tnccs-20.so
%{_libdir}/%{name}/plugins/lib%{name}-tnccs-11.so
%{_libdir}/%{name}/plugins/lib%{name}-tnccs-dynamic.so
%{_libdir}/%{name}/plugins/lib%{name}-eap-radius.so
%{_libdir}/%{name}/plugins/lib%{name}-tnc-ifmap.so
%{_libdir}/%{name}/plugins/lib%{name}-tnc-pdp.so
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/attest
%{_libexecdir}/%{name}/pt-tls-client

%files libipsec
%{_libdir}/%{name}/libipsec.so.0
%{_libdir}/%{name}/libipsec.so.0.0.0
%{_libdir}/%{name}/plugins/libstrongswan-kernel-libipsec.so
