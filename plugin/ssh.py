#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import json
import base64
import sys
import os
import traceback
import string
import random
from subprocess import check_output as qx


def list_params():
    RequestParams = [[{'key': 'pub_key', 'name': 'public key',
                       'description': 'the public key to upload to the service',
                       'type': 'textarea', 'mandatory': True}], []]
    ConfParams = [
        {'name': 'state_prefix', 'type': 'string', 'default': 'WATTS_'},
        {'name': 'host_list', 'type': 'string', 'default': ''},
        {'name': 'create_user', 'type': 'boolean', 'default': 'false'},
        {'name': 'user_prefix', 'type': 'string', 'default': 'wattsuser'},
        {'name': 'work_dir', 'type': 'string',
         'default': '/home/watts/.config/watts/plugin_ssh/'}]
    Version = "0.1.0"
    return json.dumps({'result': 'ok',
                       'conf_params': ConfParams,
                       'request_params': RequestParams,
                       'version': Version})


def create_ssh(UserId, CreateUser, UserPrefix, Params, Hosts, Prefix, WorkDir):
    if 'pub_key' in Params:
        return insert_ssh_key(UserId, CreateUser, UserPrefix, Params['pub_key'], Hosts, Prefix)
    else:
        return create_ssh_for(UserId, CreateUser, UserPrefix, Hosts, Prefix, WorkDir)


def revoke_ssh(UserId, State, Hosts):
    return delete_ssh_for(UserId, State, Hosts)


def create_ssh_for(UserId, CreateUser, UserPrefix, Hosts, Prefix, BaseWorkDir):
    Password = id_generator()
    State = "%s%s" % (Prefix, id_generator(32))
    # maybe change this to random/temp file
    WorkDir = os.path.join(BaseWorkDir, UserId)
    OutputFile = os.path.join(WorkDir, "tts_ssh_key")
    OutputPubFile = os.path.join(WorkDir, "tts_ssh_key.pub")
    EnsureWorkDir = "mkdir -p %s > /dev/null" % (WorkDir)
    RmDir = "rm -rf %s > /dev/null" % WorkDir
    # DelKey = "srm -f %s %s.pub > /dev/null"%(OutputFile,OutputFile)
    # DelKey = "shred -f %s %s.pub > /dev/null"%(OutputFile,OutputFile)
    os.system(RmDir)
    os.system(EnsureWorkDir)
    Cmd = "ssh-keygen -N %s -C %s -f %s > /dev/null" % (
        Password, State, OutputFile)
    Res = os.system(Cmd)
    if Res != 0:
        LogMsg = "the key generation '%s' failed with %d" % (Cmd, Res)
        UserMsg = "sorry, the key generation failed"
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})

    PubKey = validate_and_update_key(get_file_content(OutputPubFile), State)
    PrivKey = get_file_content(OutputFile)
    if PubKey is None:
        LogMsg = "the public key generated '%s' is not valid" % PubKey
        UserMsg = "sorry, the public key generation failed"
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})

    os.system(RmDir)

    PubKeyObj = {
        'name': 'Public Key',
        'type': 'textfile',
        'value': PubKey,
     'rows': 4}
    PrivKeyObj = {
        'name': 'Private Key',
        'type': 'textfile',
        'value': PrivKey,
        'rows': 30,
     'cols': 64}
    PasswdObj = {
        'name': 'Passphrase (for Private Key)',
        'type': 'text',
     'value': Password}
    Credential = [PrivKeyObj, PasswdObj, PubKeyObj]

    HostResult = deploy_key(UserId, PubKey, State, CreateUser, UserPrefix, Hosts)
    if HostResult['result'] == 'ok':
        HostCredential = HostResult['output']
        Credential.extend(HostCredential)
        return json.dumps(
            {'result': 'ok', 'credential': Credential, 'state': State})
    else:
        Log = HostResult['log']
        UserMsg = "the deployment failed, the error has been logged, please contact the administrator"
        LogMsg = "key deployment did fail on at least one host: '%s'" % Log
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
    return json.dumps(
        {'result': 'ok', 'credential': Credential, 'state': State})


def insert_ssh_key(UserId, CreateUser, UserPrefix, InKey, Hosts, Prefix):
    State = "%s%s" % (Prefix, id_generator(32))
    PubKey = validate_and_update_key(InKey, State)
    if PubKey is None:
        LogMsg = "the key given by the user '%s' is not valid" % InKey
        UserMsg = "sorry, the public key was not valid"
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})

    Result = deploy_key(UserId, PubKey, State, CreateUser, UserPrefix, Hosts)
    if Result['result'] == 'ok':
        Credential = Result['output']
        return json.dumps(
            {'result': 'ok', 'credential': Credential, 'state': State})
    else:
        Log = Result['log']
        UserMsg = "the deployment failed, the error has been logged, please contact the administrator"
        LogMsg = "key deployment did fail on at least one host: '%s'" % Log
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})


def validate_and_update_key(Key, State):
    if len(Key) < 3:
        return None
    KeyParts = Key.split(" ", 2)
    if len(KeyParts) != 3:
        return None
    KeyType = KeyParts[0]
    PubKey = KeyParts[1]
    if not KeyType.startswith("ssh-"):
        return None
    if len(PubKey) < 4:
        return None
    return "%s %s %s" % (KeyType, PubKey, State)


def deploy_key(UserId, Key, State, CreateUser, UserPrefix, Hosts):
    Json = json.dumps(
        {'action': 'request', 'watts_userid': UserId, 'cred_state': 'undefined',
         'params': {'state': State, 'pub_key': Key, 'create_user': CreateUser,
                    'user_prefix' : UserPrefix }
        })
    Parameter = base64.urlsafe_b64encode(Json)
    Result = execute_on_hosts(Parameter, Hosts)
    Output = []
    Log = ""
    for Json in Result:
        if 'result' in Json and Json['result'] == 'ok':
            Host = Json['host']
            Credential = Json['credential']
            for Cred in Credential:
                if Cred['name'] == 'Username':
                    Username = Cred['value']
            Output.append({'name': "user @ %s" % Host,
                           'type': 'text', 'value': Username})
        else:
            Log = "%s%s: %s; " % (Log, Json['host'], Json['log_msg'])

    if len(Output) == len(Result):
        return {'result': 'ok', 'output': Output}
    else:
        return {'result': 'error', 'log': Log}


def delete_ssh_for(UserId, State, Hosts):
    Json = json.dumps({'action': 'revoke',
                       'watts_userid': UserId,
                       'cred_state': State,
                       'params': {'create_user': False}})
    Parameter = base64.urlsafe_b64encode(Json)
    Result = execute_on_hosts(Parameter, Hosts)
    OkCount = 0
    Log = ""
    for Json in Result:
        if 'result' in Json and Json['result'] == 'ok':
            OkCount = OkCount + 1
        else:
            Log = "%s%s: %s; " % (Log, Json['host'], Json['log_msg'])
    if OkCount == len(Result):
        return json.dumps({'result': 'ok'})
    else:
        UserMsg = "the revocation failed and has been logged, please contact the administrator"
        LogMsg = "key revocation did fail on at least one host: '%s'" % Log
        return json.dumps(
            {'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})


def execute_on_hosts(Parameter, Hosts):
    # loop through all server and collect the output
    Cmd = "sudo /home/watts/.config/watts/ssh_vm.py %s" % Parameter
    Result = []
    for UserHost in Hosts:
        Host = UserHost.split("@")[1]
        Output = qx(["ssh", UserHost, Cmd])
        try:
            Json = json.loads(Output)
            Json['host'] = Host
            Result.append(Json)
        except:
            UserMsg = "Internal error, please contact the administrator"
            LogMsg = "no json result: %s"%Output
            Result.append({'result':'error', 'host':Host, 'user_msg': UserMsg, 'log_msg':LogMsg})

    return Result


def get_file_content(File):
    fo = open(File)
    Content = fo.read()
    fo.close()
    return Content


def id_generator(
        size=16,
        chars=string.ascii_uppercase +
        string.digits +
        string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


def ensure_group_list(MaybeGroups):
    if isinstance(MaybeGroups, str):
        Groups = parse_group_string(MaybeGroups)
        return Groups
    if isinstance(MaybeGroups, unicode):
        Groups = parse_group_string(MaybeGroups)
        return Groups
    if isinstance(MaybeGroups, list):
        return MaybeGroups
    else:
        return []


def parse_group_string(GroupString):
    RawGroups = GroupString.split(',')
    Groups = []
    for Group in RawGroups:
        Groups.append(Group.strip())
    return Groups


def get_loa(Oidc):
    Loa = ""
    if 'acr' in Oidc:
        Loa = Oidc['acr']
    return Loa


def get_groups(Oidc):
    Groups = []
    if 'groups' in Oidc:
        Groups = ensure_group_list(Oidc['groups'])
    return Groups


def main():
    UserMsg = "Internal error, please contact the administrator"
    try:
        if len(sys.argv) == 2:
            Json = str(sys.argv[1]) + '=' * (4 - len(sys.argv[1]) % 4)
            JObject = json.loads(str(base64.urlsafe_b64decode(Json)))

            # general information
            Action = JObject['action']
            if Action == "parameter":
                print list_params()

            else:
                State = JObject['cred_state']
                Params = JObject['params']
                ConfParams = JObject['conf_params']
                UserId = JObject['watts_userid']

                Prefix = ConfParams['state_prefix']
                WorkDir = ConfParams['work_dir']
                Hosts = ConfParams['host_list'].split()
                CreateUser = ConfParams['create_user']
                UserPrefix = ConfParams['user_prefix']

                UserInfo = JObject['user_info']
                Subject = UserInfo['sub']
                Issuer = UserInfo['iss']
                Loa = get_loa(UserInfo)

                if len(Hosts) == 0:
                    LogMsg = "the plugin has no hosts configured, use the 'host_list' parameter"
                    print json.dumps({'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
                elif Action == "request":
                    print create_ssh(UserId, CreateUser, UserPrefix, Params, Hosts, Prefix, WorkDir)
                elif Action == "revoke":
                    print revoke_ssh(UserId, State, Hosts)
                else:
                    LogMsg = "the plugin was run with an unknown action '%s'" % Action
                    print json.dumps({'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
        else:
            LogMsg = "the plugin was run without an action"
            print json.dumps({'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
    except Exception as E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin failed with %s - %s" % (str(E), TraceBack)
        print json.dumps({'result': 'error', 'user_msg': UserMsg, 'log_msg': LogMsg})
        pass

if __name__ == "__main__":
    main()
