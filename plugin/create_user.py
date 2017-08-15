#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
from grp import getgrnam



def ensure_account_exists(UserId, Prefix, SshMapFile):
    (Username, Index) = lookupUsernameId(UserId, SshMapFile)
    if Username == None:
        (Username, Index) = create_account(Index, Prefix)
    else:
        sys.exit(0)

    if Username == None:
        sys.exit(254)

    add_user_to_map_file(Username, Index, UserId, SshMapFile)
    sys.exit(0)


def lookupUsernameId(UserId, SSHMapFile):
    File = open(SSHMapFile)
    UserName = None
    HighestId = 0
    for Line in File:
        Entries = Line.split()
        if len(Entries) == 3 and Entries[0] == UserId:
            UserName = Entries[1]
        if len(Entries) == 3 and Entries[2] > HighestId:
            HighestId = int(Entries[2])
    File.close()
    return (UserName, HighestId+1)


def add_user_to_map_file(Username, Index, UserId, SshMapFile):
    Line = "%s %s %s\n"%(UserId, Username, str(Index))
    File = open(SshMapFile, "a")
    File.write(Line)
    File.close()


def create_account(Index, Prefix):
    UserName = "%s%s"%(Prefix, str(Index))
    # create a user with:
    # main group watts_user
    # with their own home directory
    # with no dedicated group
    # the shell /bin/sh
    # and uid of 2000+
    GroupExists = ensure_group_exists("watts_user")
    if GroupExists == False:
        sys.exit(2)

    Cmd = '/usr/sbin/useradd -c "WATTS USER"'
    Cmd = Cmd + ' -g watts_user --create-home --no-user-group'
    Cmd = Cmd + ' --shell /bin/sh --key UID_MIN=2000 %s > /dev/null 2>&1'%UserName
    Result = os.system(Cmd)
    if Result == 9 or Result == 2304:
        return create_account(Index+1)

    if Result == 0:
        return (UserName, Index)
    return (None, Index)

def ensure_group_exists(GroupName):
    try:
        getgrnam(GroupName)
        return True
    except Exception:
        Cmd = '/usr/sbin/groupadd --key GID_MIN=2000 %s > /dev/null 2>&1'%GroupName
        Result = os.system(Cmd)
        if Result == 0:
            return True
        pass
    return False

def main():
    try:
        Cmd = None
        if len(sys.argv) == 4:
            UserId = sys.argv[1]
            Prefix = sys.argv[2]
            SshMapFile = sys.argv[3]
            ensure_account_exists(UserId, Prefix, SshMapFile)
        else:
            sys.exit(254)
    except Exception, E:
        sys.exit(255)


if __name__ == "__main__":
    main()
