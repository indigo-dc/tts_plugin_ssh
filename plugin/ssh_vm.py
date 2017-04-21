#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import json
import base64
import sys
import os
import traceback
import string
import random
from pwd import getpwnam

def insert_ssh_key(UserName, IsDefault, InKey, State):
    UserExists = does_user_exist(UserName)
    if not UserExists:
        # dear admin, this is not the problem of tts
        LogMsg = "user %s does not exist"%UserName
        UserMsg = "user does not exist, please contact the administrator"
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

    HomeDir = get_homedir(UserName)
    SshDir = create_ssh_dir(UserName,HomeDir)
    if SshDir == None:
        UserMsg = "the ssh-directory is missing, please contact the administrator"
        LogMsg = "could not create ssh-dir %s for user %s"%(SshDir, UserName)
        return json.dumps({'result':'error','user_msg':UserMsg, 'log_msg':LogMsg})

    Key = validate_and_update_key(InKey, State)
    if Key == None:
        UserMsg = "the given public key seemed to be broken"
        LogMsg = "the public key '%s' did not validate"%InKey
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

    do_insert_key(SshDir, Key, IsDefault)
    UserNameObj = {'name':'Username', 'type':'text', 'value':UserName}
    Credential = [UserNameObj]
    return json.dumps({'result':'ok', 'credential':Credential, 'state':State})


def revoke_ssh(UserName, State):
    UserExists = does_user_exist(UserName)
    if UserExists:
        return delete_ssh_for(UserName,State)
    else:
        # dear admin, this is not the problem of tts
        LogMsg = "user %s does not exist"%UserName
        UserMsg = "user does not exist, please contact the administrator"
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})


def get_homedir(UserName):
    HomeDir = getpwnam(UserName).pw_dir
    return HomeDir

def validate_and_update_key(Key, State):
    if len(Key) < 3:
        return None
    KeyParts = Key.split(" ")
    if len(KeyParts) != 3:
        return None
    KeyType = KeyParts[0]
    PubKey = KeyParts[1]
    if not KeyType.startswith("ssh-"):
        return None
    if len(PubKey) < 4:
        return None
    return "%s %s %s"%(KeyType, PubKey, State)

def do_insert_key(SshDir, Key, IsDefault):
    AuthorizedFile = os.path.join(SshDir,"authorized_keys")
    Prepend='command="cat /etc/tts/ssh.msg",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty '
    if not IsDefault:
        Prepend='no-port-forwarding,no-X11-forwarding,no-agent-forwarding '

    Cmd = "echo '%s %s' >> %s"%(Prepend,Key,AuthorizedFile)
    os.system(Cmd)

def delete_ssh_for(UserName, State):
    UserMsg = "revocation of ssh-key failed"
    LogMsg = "removal of public key failed: the cmd '%s' failed with %d"
    HomeDir = get_homedir(UserName)
    SshDir = create_ssh_dir(UserName,HomeDir)
    if SshDir == None:
        return json.dumps({'error':'ssh_dir_missing'})
    AuthorizedFile = os.path.join(SshDir,"authorized_keys")
    BackupFile = "%s%s"%(AuthorizedFile,".backup")
    TempFile = "%s%s"%(AuthorizedFile,".tts")
    Copy = "cp %s %s"%(AuthorizedFile,BackupFile)
    Remove = "grep -v %s %s > %s"%(State,BackupFile,AuthorizedFile)
    Delete = "rm -f %s"%BackupFile
    Res = os.system(Copy)
    if Res != 0 :
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg%(Copy, Res)})

    Res = os.system(Remove)
    if Res != 0 and Res != 256 :
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg%(Remove, Res)})

    Res = os.system(Delete)
    if Res != 0 :
        return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg%(Delete, Res)})

    return json.dumps({'result':'ok'})



def create_ssh_dir(UserName,HomeDir):
    SshDir=os.path.join(HomeDir,".ssh/")
    AuthorizedFile=os.path.join(SshDir,"authorized_keys")
    if not os.path.exists(SshDir):
        CreateSshDir = "mkdir -p %s"%SshDir
        if os.system(CreateSshDir) != 0:
            return None
    if not os.path.exists(AuthorizedFile):
        CreateFile = "touch %s"%AuthorizedFile
        if os.system(CreateFile) != 0:
            return None

    # always enfore mod and ownership
    ChOwnSshDir = "chown %s %s"%(UserName,SshDir)
    ChModSshDir = "chmod 700 %s"%SshDir
    ChOwnAuthFile = "chown %s %s"%(UserName,AuthorizedFile)
    ChModAuthFile = "chmod 600 %s"%AuthorizedFile
    if os.system(ChOwnSshDir) != 0:
        return None
    if os.system(ChModSshDir) != 0:
        return None
    if os.system(ChModAuthFile) != 0:
        return None
    if os.system(ChOwnAuthFile) != 0:
        return None

    return SshDir



def does_user_exist(UserName):
    # user has been created
    try:
        SysUid = getpwnam(UserName).pw_uid
        return True
    except Exception:
        return False

def lookupPosix(UserId):
    File = open("/home/tts/.config/tts/ssh_map")
    Result = (None, False)
    for Line in File :
        Entries = Line.split()
        if len(Entries) == 2 and Entries[0] == UserId :
            File.close()
            return (Entries[1], False)
        elif len(Entries) == 2 and Entries[0] == "default" :
            Result = (Entries[1], True)
    File.close()
    return Result


def main():
    try:
        Cmd = None
        if len(sys.argv) == 2:
            Json = str(sys.argv[1])+ '=' * (4 - len(sys.argv[1]) % 4)
            JObject = json.loads(str(base64.urlsafe_b64decode(Json)))

            #general information
            Action = JObject['action']
            if Action == "parameter":
                print list_params()

            else:
                State = JObject['cred_state']
                Params = JObject['params']
                UserId = JObject['watts_userid']
                (UserName, IsDefault) = lookupPosix(UserId)
                if UserName == None:
                    UserMsg = "username was not found, seems like you are not supported"
                    LogMsg = "no mapping for userid '%s'"%UserId
                    print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
                elif UserName == 'root':
                    UserMsg = "username was not found, seems like you are not supported"
                    LogMsg = "not supporting mapping to root: '%s'"%UserId
                    print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
                elif Action == "request":
                    PubKey = Params['pub_key']
                    InState = Params['state']
                    print insert_ssh_key(UserName, IsDefault, PubKey, InState)
                elif Action == "revoke":
                    print revoke_ssh(UserName, State)
                else:
                    UserMsg = "Internal error, please contact the administrator"
                    LogMsg = "the plugin was run with an unknown action '%s'"%Action
                    print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
        else:
            UserMsg = "Internal error, please contact the administrator"
            LogMsg = "the plugin was run without an action"
            print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
    except Exception, E:
        TraceBack = traceback.format_exc(),
        UserMsg = "Internal error, please contact the administrator"
        LogMsg = "the plugin crashed: %s - %s"%(str(E), TraceBack)
        print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})
        pass

if __name__ == "__main__":
    main()
