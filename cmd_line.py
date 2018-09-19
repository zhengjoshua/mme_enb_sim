import os
import time
import re
import argparse
import atexit
import cmd
import sys
import logging
from queue import Queue
from mme import Server
from threading import Thread


def is_digit(x):
    try:
        x = int(x)
        return isinstance(x, int)
    except ValueError:
        return False


def check_ipv4(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False


def check_value(value):
    print("checking", value)


def check_imsi(imsi):
    if not all([is_digit(x) for x in imsi]):
        raise ParamValueError(imsi, "Invalid argument imsi")
    if not 6 <= len(imsi) <= 15:
        raise ParamValueError(imsi, "Invalid argument imsi length")


def check_mei(mei):
    if not all([is_digit(x) for x in mei]):
        raise ParamValueError(mei, "Invalid argument mei")
    if not 0 <= len(mei) <= 16:
        raise ParamValueError(mei, "Invalid argument mei length")


def check_bearer_context(bearer_context):
    try:
        bearer_id, arp, qci, mbr_uplink, mbr_downlink, gbr_uplink, gbr_downlink = bearer_context.split(',')
    except ValueError:
        raise ParamValueError(bearer_context, "argument missing some fields bearer_context")

    if not all([1 <= int(arp) <= 15, 1 <= int(qci) <= 9, is_digit(mbr_uplink), is_digit(mbr_downlink),
                is_digit(gbr_uplink), is_digit(gbr_downlink)]):
        raise ParamValueError(bearer_context, "Invalid argument bearer_context")


ImplementedParameters = {"imsi": check_imsi,
                         "cbresp-cause": check_value,
                         "dbresp-cause": check_value,
                         "apn": check_value,
                         "pdn-type": check_value,
                         "bearer-context": check_bearer_context,
                         "default-bearer-context": check_bearer_context,
                         "timezone": check_value,
                         "apn-ambr": check_value,
                         "selection-mode": check_value,
                         "msisdn": check_value,
                         "mei": check_mei,
                         "apn-restriction-type": check_value,
                         "uli-mcc-mnc-tai": check_value,
                         "uli-mcc-mnc-ecgi": check_value,
                         "indication": check_value
                         }


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class ParamNameError(Error):
    def __init__(self, name, message):
        self.name = name
        self.message = message

    def __str__(self):
        info = "{m}: {n}".format(m=self.message, n=self.name)
        return info


class ParamValueError(Error):
    def __init__(self, value, message):
        self.value = value
        self.message = message

    def __str__(self):
        info = "{m}: {v}".format(m=self.message, v=self.value)
        return info


class ClientCMD(cmd.Cmd):
    def __init__(self):
        super(ClientCMD, self).__init__()
        self.cmd_queue = Queue()
        self.server = None
        self.prompt = 'CLI> '
        try:
            import readline
        except ImportError:
            print("Can't load Python libreadline or completer")
        else:
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            histfile = os.path.join(os.path.expanduser("~"), ".mme_enb_sim_history")
            try:
                readline.read_history_file(histfile)
                readline.set_history_length(100)
            except FileNotFoundError:
                pass
            atexit.register(readline.write_history_file, histfile)

        parser = argparse.ArgumentParser()
        parser.add_argument('-t', action='store', dest='template_file', help="Template file", required=True)
        parser.add_argument('-c', action='store', dest='config_file', help="Configuration file", required=True)
        args = parser.parse_args()
        self.template_file = args.template_file
        self.config_file = args.config_file
        self.log_file = args.config_file.split('.')[0] + '.log'
        self.loglevel_dict = {
            1: "DEBUG",
            2: "INFO",
            3: "WARNING",
            4: "ERROR"
        }
        self.log_level = 2
        self.intro = """
Welcome to mme_enb_sim (1.0) built on Sep.2018.
Copyright (c) Nokia-Sbell. All rights reserved.
Report bugs or RFE to : jun.c.zheng@nokia-sbell.com.
Template file         : {t}
Config file           : {c}
Default log level     : {l}
Type 'help' for more information.
""".format(t=self.template_file, c=self.config_file, l=self.loglevel_dict[self.log_level])

    def do_clear(self, args):
        """
        clear profile <prof-id> <attrib> - Clear the value of the specified profile attribute.
        clear session <imsi> - Clean up session record for the given UE.
        clear session-group <grp-id> [procs|retrans] - Clean up session record of all UE's in the given group.
        clear session-state {imsi <imsi>| group <grp-id>} - Restore the session state to active/idle.
        clear stats {all|s11|s1u|s3|s5|s5u|ue|nemo|dhcp|itc|interactive-mode} - Clear global statistics.
        clear stats bearer <imsi> <ebi> - Clear the S1-u statistics of the given bearer.
        clear stats group <grp-id> - Clear the S11 statistics of all sessions in the given group.
        clear stats session <imsi> - Clear the S11 statistics of the given session.
        """
        pass

    def complete_clear(self, text, line, begidx, endidx):
        options = ["peers", "stats", "sessions"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_create(self, args):
        """
        create profile <prof-id> [from <prof-id>] - Create a new configuration profile.
        create session {imsi <imsi> | group <grp-id>} - Create specified session(s) without message sending.
        create session-group <grp-id> <prof-id> <size> - Create a session group of given size sharing specified configuration profile.
        """
        cmd_args_list = args.split()
        if len(cmd_args_list) == 0:
            pass
        elif len(cmd_args_list) < 2:
            print("incomplete cmd: ", "create " + args)
        elif len(cmd_args_list) in [2, 3, 4, 5]:
            if cmd_args_list[0].lower() in ['profile', "session-group"]:
                if cmd_args_list[0].lower() == "session-group":
                    if len(cmd_args_list) < 4:
                        print("incomplete cmd: ", "create " + args)
                        return
                    else:
                        pass
                cmd_args_list.insert(0, 'create')
                self.server.events_queue.put(cmd_args_list)
            else:
                print("*** Unknown syntax: ", "create " + ' '.join(cmd_args_list))
                print("Use 'help send' for detail usage")
        else:
            print("*** Unknown syntax: ", "create " + ' '.join(cmd_args_list))
            print("Refer to 'help create' for detail usage")

    def complete_create(self, text, line, begidx, endidx):
        options = ["profile", "session", "session-group"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_delete(self, args):
        """
        clear <peers> {peer-address}  - Disconnect peer locally
        clear <stats> {peer-address}  - Clear statistics of peers
        clear <sessions> {imsi}       - Removes all active sessions
        """
        pass

    def complete_delete(self, text, line, begidx, endidx):
        options = ["peers", "stats", "sessions"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_exec(self, args):
        """
        exec <file> - Execute commands from the specified file.
        """
        pass

    def complete_exec(self, text, line, begidx, endidx):
        options = ["peers", "stats", "sessions"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_proc(self, args):
        """
        proc attach {imsi <imsi>|group <grp-id>} - Start E-UTRAN Attach procedure for the given UE or session group.
        """
        cmd_args_list = args.split()
        if len(cmd_args_list) == 0:
            pass
        elif len(cmd_args_list) == 1:
            if cmd_args_list[0].lower() in ["attach", "detach", "handover"]:
                print("incomplete cmd: ", "proc " + args)
            else:
                print("*** Unknown syntax: ", "proc " + ' '.join(cmd_args_list))
        elif len(cmd_args_list) == 2:
            if cmd_args_list[0].lower() in ["attach", "detach", "handover"]:
                if cmd_args_list[1].lower() in ["imsi", "group"]:
                    print("incomplete cmd: ", "proc " + args)
                else:
                    print("*** Unknown syntax: ", "proc " + ' '.join(cmd_args_list))
            else:
                print("*** Unknown syntax: ", "proc " + ' '.join(cmd_args_list))
        elif len(cmd_args_list) in [3, 4]:
            if cmd_args_list[0].lower() in ["attach", "detach", "handover"]:
                if cmd_args_list[1].lower() in ["imsi", "group"]:
                    cmd_args_list.insert(0, "proc")
                    self.server.events_queue.put(cmd_args_list)
            else:
                print("*** Unknown syntax: ", "proc " + ' '.join(cmd_args_list))
                print("Use 'help proc' for detail usage")
        else:
            print("*** Unknown syntax: ", "proc " + ' '.join(cmd_args_list))
            print("Refer to 'help proc' for detail usage")

    def complete_proc(self, text, line, begidx, endidx):
        options = ["attach", "detach", "handover"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_set(self, args):
        """
        set profile <prof-id> <attrib> <value> [<overwrite-id>] - Set the value of the specified profile attribute.
        """
        cmd_args_list = args.split()
        if len(cmd_args_list) == 0:
            pass
        elif len(cmd_args_list) <4:
            print("incomplete cmd: ", "set " + ' '.join(cmd_args_list))
        elif len(cmd_args_list) in [4, 5]:
            if cmd_args_list[0].lower() in ["profile", ]:
                if cmd_args_list[0].lower() == "profile":
                    try:
                        self.check_parameter(cmd_args_list[2], cmd_args_list[3])
                    except ParamNameError as error:
                        print(error)
                        return
                    except ParamValueError as error:
                        print(error)
                        return
                cmd_args_list.insert(0, 'set')
                self.server.events_queue.put(cmd_args_list)
            else:
                print("*** Unknown syntax: ", "set " + ' '.join(cmd_args_list))
                print("Use 'help set' for detail usage")
        else:
            print("*** Unknown syntax: ", "set " + ' '.join(cmd_args_list))
            print("Refer to 'help set' for detail usage")

    def complete_set(self, text, line, begidx, endidx):
        options = ["profile",]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_show(self, args):
        """
        show bearer {enb|sgw} <teid> - Show bearer information given its downlink or uplink TEID.
        show mme [id/address]        - Show MME information given its id or address.
        show profile <prof-id> [params] - Show profile information/ parameters.
        show session pdn <imsi> {<lbi>}
        """
        cmd_args_list = args.split()
        if len(cmd_args_list) == 0:
            pass
        elif len(cmd_args_list) in [1, 2, 3, 4]:
            if cmd_args_list[0].lower() in ["bearer", "mme", "profile", "session"]:
                cmd_args_list.insert(0, "show")
                self.server.events_queue.put(cmd_args_list)
            else:
                print("*** Unknown syntax: ", "show " + ' '.join(cmd_args_list))
                print("Use 'help show' for detail usage")
        else:
            print("*** Unknown syntax: ", "show " + ' '.join(cmd_args_list))
            print("Refer to 'help show' for detail usage")

    def complete_show(self, text, line, begidx, endidx):
        options = ["bearer", "mme", "profile"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def do_send(self, args):
        """
        send <rar> {imsi}  - Send RAR message for sessions
        send <asr> <imsi>  - Send ASR message for session
        send <str> <imsi>  - Send STR message for session
        send <mar> <imsi>  - Send MAR message for session
        send <dpr> {peer}  - Show DPR message to peers
        """
        pass

    def complete_send(self, text, line, begidx, endidx):
        pass

    def do_recfg(self, args):
        """
        recfg  - Reload template file content
        """
        pass

    def do_tools(self, args):
        """
        tools parse-msg-dump <file-name> - Parse message dump from given file. Messages are separated by blank lines.
        """
        pass

    def complete_tools(self, text, line, begidx, endidx):
        options = ["peers", "stats", "sessions"]
        if not text:
            completions = options[:]
        else:
            completions = [option for option in options if option.startswith(text)]
        return completions

    def postcmd(self, stop, line):
        time.sleep(0.1)

    def emptyline(self):
        pass

    def do_loglevel(self, args):
        """
        loglevel <1..4>  - Change log level
        1 : DEBUG
        2 : INFO
        3 : WARNING
        4 : ERROR
        """
        cmd_args_list = args.split()
        if len(cmd_args_list) == 1:
            logger = logging.getLogger()
            level = cmd_args_list[0]
            if int(level) < 1 or int(level) > 4:
                print("Invalid loglevel:", level)
                print("Usage: loglevel <1..4>, use 'help loglevel' for details")
                return
            self.log_level = int(level)
            logger.setLevel(self.log_level * 10)
            info = 'Log level set to : {level}'.format(level=self.loglevel_dict[self.log_level])
            print(info)
            logging.info(info)
        else:
            print("Usage: loglevel <1..4>, use 'help loglevel' for details")

    def do_exit(self, args):
        """
        exit  - Terminate the program
        """
        logging.info("Program exit")
        print("Bye!")
        sys.exit(0)

    @staticmethod
    def check_parameter(name, value):
        if name not in ImplementedParameters.keys():
            raise ParamNameError(name, "parameter not support")
        else:
            func = ImplementedParameters[name]
            func(value)

    def start_logging(self):
        logging.basicConfig(filename=self.log_file, filemode='a', level=self.log_level * 10,
                            datefmt="%Y-%m-%d %H:%M:%S",
                            format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')


if __name__ == "__main__":
    client_cmd = ClientCMD()
    client_cmd.start_logging()
    info = "Program start"
    logging.info(info)

    server = Server(client_cmd.config_file, client_cmd.template_file)
    mme_thread = Thread(target=server.start, daemon=True)
    mme_thread.start()
    time.sleep(0.1)

    if server.is_alive():
        client_cmd.server = server
        client_cmd.cmdloop()
    else:
        logging.info("Program exit")
        print("mme_enb_sim failed to start.")
        print("Bye!")
        sys.exit(0)


