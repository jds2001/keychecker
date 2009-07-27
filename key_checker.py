#!/usr/bin/python -tt
#
#
# Copyright (C) 2009 Jon Stanley
#
# The getSigInfo function is lifted directly from yum
# Copyright (C) 2003 Duke University
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# bump this when doing a release
version = '%prog 0.1'
import rpm
import sys
import errno
try:
    from rpmUtils.miscutils import getSigInfo
except ImportError:
    import locale
    def getSigInfo(hdr):
        """checks signature from an hdr hand back signature information and/or
        an error code"""
        locale.setlocale(locale.LC_ALL, 'C')
        string = '%|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|'
        siginfo = hdr.sprintf(string)
        if siginfo != '(none)':
            error = 0
            sigtype, sigdate, sigid = siginfo.split(',')
        else:
            error = 101
            sigtype = 'MD5'
            sigdate = 'None'
            sigid = 'None'
        infotuple = (sigtype, sigdate, sigid)
        return error, infotuple

from optparse import OptionParser

ts=rpm.TransactionSet()

def buildKeyList():
    '''Build a dict of public keys in the rpm database'''
    keys = ts.dbMatch(rpm.RPMTAG_NAME, 'gpg-pubkey')
    for hdr in keys:
        pubkeys[hdr[rpm.RPMTAG_VERSION]]=hdr[rpm.RPMTAG_SUMMARY][4:].split('<',1)[0].rstrip()

def getPkgNevra(hdr):
    '''Return a formatted string of the nevra of a header object'''
    if hdr[rpm.RPMTAG_EPOCH]:
        return '%s-%s:%s-%s.%s' % ( hdr[rpm.RPMTAG_NAME], hdr[rpm.RPMTAG_EPOCH],
                hdr[rpm.RPMTAG_VERSION], hdr[rpm.RPMTAG_RELEASE],
                hdr[rpm.RPMTAG_ARCH])
    else:
        return '%s-%s-%s.%s' % ( hdr[rpm.RPMTAG_NAME], hdr[rpm.RPMTAG_VERSION],
                hdr[rpm.RPMTAG_RELEASE], hdr[rpm.RPMTAG_ARCH] )

def getSig(hdr):
    '''Given an rpm header object, extract the signing key, if any.

    Returns a tuple of the name of the package nevra, and the name of the
    signing key.'''
    if hdr[rpm.RPMTAG_DSAHEADER] or hdr[rpm.RPMTAG_RSAHEADER]:
        keyid = getSigInfo(hdr)[1][2][16:]
        try:
            return (getPkgNevra(hdr), pubkeys[keyid])
        except KeyError:
            pubkeys[keyid] = 'Unknown key %s' % keyid
            return (getPkgNevra(hdr), pubkeys[keyid])
    else:
        return (getPkgNevra(hdr), 'unsigned')

def getPkg(name=None):
    '''Get package signing keys from the RPM database

    Optionally accepts a name of a package, if present, restrict the search to
    all instances of that package name, otherwise, the entire RPM database is
    processed. Ignores entries that are GPG public keys in the rpmdb'''
    if name:
        mi = ts.dbMatch(rpm.RPMTAG_NAME, name)
    else:
        mi = ts.dbMatch()
    exists = False
    for hdr in mi:
        exists = True
        if hdr[rpm.RPMTAG_NAME] == 'gpg-pubkey':
            continue
        nevra, key = getSig(hdr)
        try:
            pkgs[key].append(nevra)
        except KeyError:
            pkgs[key] = []
            pkgs[key].append(nevra)

    if not exists:
        sys.stderr.write('No such package %s\n' % name)

def csvOutput(pkgs):
    '''Output data in csv format'''

    for pkg in sorted(pkgs.iteritems()):
        if pkg[1]:
            for pkginstance in sorted(pkg[1]):
                try:
                    print '%s,%s' % (pkginstance,pkg[0])
                except IOError, e:
                    if e.errno == errno.EPIPE:
                        sys.exit(1)
                    else:
                        raise

def listOutput(pkgs):
    '''Output data in separated list format'''

    for pkg in sorted(pkgs.iteritems()):
        if pkg[1]:
            print pkg[0]
            print '-' * len(pkg[0])
            for pkginstance in sorted(pkg[1]):
                try:
                    print pkginstance
                except IOError, e:
                    if e.errno == errno.EPIPE:
                        sys.exit(1)
                    else:
                        raise
            print

if __name__ == '__main__':
    usage = '%prog [options] pkg1 pkg2...'
    parser = OptionParser(usage, version=version)
    parser.add_option('-m', '--machine-readable', action='store_true',
        dest='mr', help='Produce machine readable output')
    options, args = parser.parse_args()
    pubkeys = {}
    buildKeyList()
    pkgs = {}
    for keyname in pubkeys.itervalues():
        pkgs[keyname] = []
    pkgs['unsigned'] = []
    if len(args) != 0:
        for pkg in args:
            getPkg(pkg)
    else:
        getPkg()
    if options.mr:
        csvOutput(pkgs)
    else:
        listOutput(pkgs)
