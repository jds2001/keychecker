#!/usr/bin/python
import rpm, sys
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
pubkeys={}
pubkeys['unknown'] = 'Unknown signing key'

def buildKeyList():
    keys = ts.dbMatch(rpm.RPMTAG_NAME, 'gpg-pubkey')
    for hdr in keys:
        pubkeys[hdr[rpm.RPMTAG_VERSION]]=hdr[rpm.RPMTAG_SUMMARY][4:].split('<',1)[0].rstrip()
def getPkgNevra(hdr):
    if hdr[rpm.RPMTAG_EPOCH]:
        return '%s-%s:%s-%s.%s' % ( hdr[rpm.RPMTAG_NAME], hdr[rpm.RPMTAG_EPOCH],
                hdr[rpm.RPMTAG_VERSION], hdr[rpm.RPMTAG_RELEASE],
                hdr[rpm.RPMTAG_ARCH])
    else:
        return '%s-%s-%s.%s' % ( hdr[rpm.RPMTAG_NAME], hdr[rpm.RPMTAG_VERSION],
                hdr[rpm.RPMTAG_RELEASE], hdr[rpm.RPMTAG_ARCH] )
def getSig(hdr):
    if hdr[rpm.RPMTAG_DSAHEADER]:
        keyid = getSigInfo(hdr)[1][2][16:]
        try:
            return (getPkgNevra(hdr), pubkeys[keyid])
        except KeyError:
            pubkeys[keyid] = 'Unkown key %s' % keyid
            return (getPkgNevra(hdr), pubkeys[keyid])
    else:
        return (getPkgNevra(hdr), 'unsigned')
def getPkg(name=None):
    if name:
        mi=ts.dbMatch(rpm.RPMTAG_NAME, name)
    else:
        mi=ts.dbMatch()
    exists = False
    for hdr in mi:
        exists = True
        if hdr[rpm.RPMTAG_NAME] == 'gpg-pubkey': continue
        nevra, key = getSig(hdr)
        try:
            pkgs[key].append(nevra)
        except KeyError:
            pkgs[key] = []
            pkgs[key].append(nevra)

    if not exists:
        sys.stderr.write('No such package %s\n' % name)

if __name__ == '__main__':
    usage = '%prog [options] pkg1 pkg2...'
    parser = OptionParser(usage)
    parser.add_option('-m', '--machine-readable', action='store_true',
        dest='mr', help='Produce machine readable output')
    options, args = parser.parse_args()
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
        for pkg in pkgs.iteritems():
            if pkg[1]:
                for pkginstance in pkg[1]:
                    print '%s,%s' % (pkginstance, pkg[0])
    else:
        for pkg in pkgs.iteritems():
            if pkg[1]:
                print pkg[0]
                print '-' * len(pkg[0])
                for pkginstance in pkg[1]:
                    print pkginstance
                print

