#!/usr/bin/python
import rpm, rpmUtils.miscutils, sys
from optparse import OptionParser

ts=rpm.TransactionSet()
pubkeys={}
pubkeys['unknown'] = 'Unknown signing key'

def buildKeyList():
    keys = ts.dbMatch(rpm.RPMTAG_NAME, 'gpg-pubkey')
    for hdr in keys:
        pubkeys[hdr[rpm.RPMTAG_VERSION]]=hdr[rpm.RPMTAG_SUMMARY][4:].rsplit('<',1)[0].rstrip()
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
        keyid = rpmUtils.miscutils.getSigInfo(hdr)[1][2][16:]
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

