#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import sys
import traceback
from grp import getgrnam



def ensure_account_exists(WattsId, Prefix, MapFile):
    Username = lookupPosix(WattsId, MapFile)
    if Username == None:
        Index = get_next_index(MapFile)
        Username = create_account(Index, Prefix)
    else:
        sys.exit(0)

    if Username == None:
        sys.exit(254)

    add_user_to_map_file(WattsId, Username, MapFile)


def add_user_to_map_file(WattsId, Username, MapFile):
    Posix = lookupPosix(WattsId, MapFile)
    if Posix == None:
        Line = "%s %s\n"%(WattsId, Username)
        File = open(MapFile, "a")
        File.write(Line)
        File.close()
    sys.exit(0)


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
        return create_account(Index+1, Prefix)

    if Result == 0:
        return UserName
    return None

def ensure_map_file_exist(MapFile):
    if not os.path.isfile(MapFile):
        File = open(MapFile, "w+")
        File.write("#this is a WaTTS mapping file\n")
        File.close()


def get_homedir(UserName):
    HomeDir = getpwnam(UserName).pw_dir
    return HomeDir


def lookupPosix(WattsId, MapFile):
    ensure_map_file_exist(MapFile)
    File = open(MapFile, "r")
    for Line in File:
        Entries = Line.split()
        if len(Entries) == 2 and Entries[0] == WattsId:
            File.close()
            return Entries[1]
    File.close()
    return None

def lookupWattsId(UserName, MapFile):
    ensure_map_file_exist(MapFile)
    File = open(MapFile, "r")
    for Line in File:
        Entries = Line.split()
        if len(Entries) == 2 and Entries[1] == UserName:
            File.close()
            return Entries[0]
    File.close()
    return None

def get_next_index(MapFile):
    File = open(MapFile, "r")
    Index = 1
    for Line in File:
        Index = Index +1
    return Index


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

def print_help():
    print """usage:
    watts-mapfile <action> [<params>]+

    add <watts-id> <username> <mapfile> - add a line to the mapfile
    lookup <watts-id> <mapfile> - lookup a local username using the watts-id
    wattsid <username> <mapfile> - lookup the watts-id of a given local username
    addcreate <watts-id> <prefix> <mapfile> - add a line and create user if it not exist
    """
    sys.exit(222)

def main():
    try:
        Cmd = None
        if len(sys.argv) < 2:
            print_help()

        Action = sys.argv[1]
        if Action == "add" and len(sys.argv) == 5 :
            WattsId = sys.argv[2]
            UserName = sys.argv[3]
            MapFile = sys.argv[4]
            add_user_to_map_file(WattsId, UserName, MapFile)

        if Action == "lookup" and len(sys.argv) == 4 :
            WattsId = sys.argv[2]
            MapFile = sys.argv[3]
            UserName = lookupPosix(WattsId, MapFile)
            if UserName  != None:
                print "%s"%UserName
            sys.exit(0)

        if Action == "wattsid" and len(sys.argv) == 4 :
            UserName = sys.argv[2]
            MapFile = sys.argv[3]
            WattsId = lookupWattsId(UserName, MapFile)
            if WattsId  == None:
                sys.exit(240)

            print "%s"%WattsId
            sys.exit(0)

        if Action == "addcreate" and len(sys.argv) == 5 :
            WattsId = sys.argv[2]
            Prefix = sys.argv[3]
            MapFile = sys.argv[4]
            ensure_account_exists(WattsId, Prefix, MapFile)
            sys.exit(0)

        else:
            print_help()

    except Exception as E:
        TraceBack = traceback.format_exc(),
        print "sorry, I crashed: %s - %s" % (str(E), TraceBack)
        sys.exit(255)


if __name__ == "__main__":
    main()
