"""
Seperated-out classes and functions so the main script doesn't look
so messy. But everything's messy so I guess it doesn't matter.
"""

import sys
import os
import re
import argparse
import smtplib
from email.mime.text import MIMEText
from os.path import exists as exists
from os import path as path, makedirs as makedirs
from sys import exc_info as exc_info
from pathlib import Path
from datetime import datetime
from inspect import currentframe
from functools import reduce
from uuid import uuid4
from hashlib import sha1
from typing import Union
import ssl
import yaml

# pylint: disable=line-too-long


def print_and_log(
    self_name: str,
    print_string: Union[str, list],
    log_file: str = "",
    settings: "ScriptGlobals" = None,
    append_mail: bool = True,
):
    """
    Prints a string to stdout and logs it to the file specified in the config.
    """

    if not log_file or log_file == "":
        log_file = "/dev/null"
    to_print = ""
    if isinstance(print_string, list):
        for print_item in print_string:
            to_print += f"{print_item}"
            if print_string.index(print_item) != len(print_string) - 1:
                to_print += "\n"
    elif isinstance(print_string, str):
        to_print = f"{print_string}"
    else:
        to_print = str(f"{print_string}")
    print_self_name = f"{str(currentframe().f_code.co_name)}()"
    logtime = str(datetime.now())
    timestamped_log_line = f"{logtime}| {self_name}: {to_print}"
    print(timestamped_log_line)

    try:
        with open(file=log_file, mode="a", encoding="ascii") as out_file:
            out_file.write(str(timestamped_log_line))
            out_file.write("\n")
        out_file.close()
        append_mail_message(
            append_msg=timestamped_log_line, settings=settings, append=append_mail
        )
    except NameError:
        if self_name == "read_yaml_file()":
            pass
        else:
            debug_msg = f"{logtime}| {print_self_name}: DEBUG: log_file variable is undefined, no logging will occur"
            append_mail_message(
                append_msg=timestamped_log_line, settings=settings, append=append_mail
            )
            print(debug_msg)
    except Exception as e:
        error_line = f"Unknown error: {str(e)}"
        unknown_error = f"{logtime}| {print_self_name}: {error_line}"
        append_mail_message(
            append_msg=timestamped_log_line, settings=settings, append=append_mail
        )
        print(unknown_error)


## DoctDict class below taken from:
## https://stackoverflow.com/questions/39463936/python-accessing-yaml-values-using-dot-notation/39485868#39464072
##
## It's silly to reinvent the wheel, and this is a roughly circular object that rolls.
## It's also silly that dot notation for YAML and JSON isn't built in to Python by now, but that's a different rant.


class DotDict(dict):
    """
    Dot notation access to dictionary keys. Why doesn't Python have this already?
    Why do I gotta roll my own? C'mon.
    """

    def __getattr__(self, k):
        self_name = f"{str(currentframe().f_code.co_name)}()"
        try:
            v = self[k]
        except KeyError:
            # return super().__getattr__(k)
            print_and_log(self_name, f"KeyError: {k}, returning None for key")
            return super().get(None)
        if isinstance(v, dict):
            return DotDict(v)
        return v

    def __getitem__(self, k):
        if isinstance(k, str) and "." in k:
            k = k.split(".")
        if isinstance(k, (list, tuple)):
            return reduce(lambda d, kk: d[kk], k, self)
        return super().__getitem__(k)

    def get(self, k, default=None):
        if isinstance(k, str) and "." in k:
            try:
                return self[k]
            except KeyError:
                return default
        return super().get(k, default=default)


class Config(DotDict):
    """Reads a YAML file and returns a DotDict object."""

    def __init__(self, config_input_file):
        self_name = f"{str(currentframe().f_code.co_name)}()"
        with open(file=config_input_file, mode="r", encoding="ascii") as file:
            try:
                # super().__init__(yaml.load(file, Loader=yaml.FullLoader))

                # Yes, I know you shouldn't do this, but it's necessary for older versions of PyYAML, like
                # what ships with RHEL8. Comment the line below and uncomment the line above if you're using
                # a newer version of PyYAML that supports the Loader argument.
                super().__init__(yaml.load(file))
            except:
                error_line = (
                    f"Error loading file at {config_input_file} (Terminating error): {exc_info()[0]}"
                )
                print_and_log(self_name, error_line)
                raise


class SELinuxMatch:
    """Class to hold SELinux match data."""

    matches = []

    def __init__(self, se_match: list, matchnumber: int):
        self.match = se_match
        self.matchtime = datetime.isoformat(datetime.now())
        self.matchnumber = matchnumber
        self.full_message = se_match[0][0]
        self.day = se_match[0][1]
        self.time = se_match[0][2]
        self.hostname = se_match[0][3]
        self.short_message = se_match[0][4]
        self.process = se_match[0][5]
        self.capability = se_match[0][6]
        self.uuid = uuid4()
        self.uuid_str = str(self.uuid)
        self.len = self.__len__()
        self.length = self.len
        hextring = f"{self.hostname} {self.process} {self.capability}"
        self.hexdigest = sha1(hextring.encode()).hexdigest()
        self.modulename = f"{se_match[0][9]}_{self.hexdigest}.pp"
        self.ausearch = se_match[0][7]
        self.audit2allow = f"{se_match[0][9]}_{self.hexdigest}"
        self.duplicate = False
        self.matches.append(self)

    def __str__(self):
        return f"Matched line: {self.full_message}\n"

    def __repr__(self):
        return f"Matched line: {self.full_message}\n"

    def __eq__(self, other):
        return self.full_message == other

    def __ne__(self, other):
        return self.full_message != other

    def __hash__(self):
        return hash(self.full_message)

    def __lt__(self, other):
        return self.full_message < other

    def __le__(self, other):
        return self.full_message <= other

    def __gt__(self, other):
        return self.full_message > other

    def __ge__(self, other):
        return self.full_message >= other

    def __contains__(self, item):
        return item in self.full_message

    def __len__(self):
        return len(self.full_message)

    def __reversed__(self):
        return reversed(self.full_message)

    def __add__(self, other):
        return self.full_message + other

    def __radd__(self, other):
        return other + self.full_message

    def __iadd__(self, other):
        self.full_message += other
        return self

    def __mul__(self, other):
        return self.full_message * other

    def __rmul__(self, other):
        return other * self.full_message

    def __imul__(self, other):
        self.full_message *= other
        return self

    def __sizeof__(self):
        return


class SELinuxMailMsg:
    """
    Class to hold alert email data.
    This class constructs an object with the properties of the email message to be sent.
    The contents of the 'bodymessage' attribute of an instantiated SELinuxMailMsg object represents
    the body of the email sent when the send_alert_email() function is called.
    The 'bodymessage' attribute is appended to each time the print_and_log() function is called, unless
    the 'append_mail' parameter is set to False.
    """

    def __init__(
        self,
        sender: str = None,
        recipients: Union[str, list] = None,
        smtpserver: str = None,
        subject: str = None,
        bodymessage: list = None,
        modules_generated: bool = False,
        num_modules_generated: int = 0,
        num_matches: int = 0,
        num_lines: int = 0,
        terminating_error: bool = False,
    ):

        self.sender = sender
        self.recipients = recipients
        self.smtpserver = smtpserver
        self.subject = subject
        self.bodymessage = bodymessage or []
        self.modules_generated = modules_generated
        self.num_modules_generated = num_modules_generated
        self.num_matches = num_matches
        self.num_lines = num_lines
        self.duplicates = 0
        self.terminating_error = terminating_error

    def __str__(self):
        return f"SELinuxMailMsg: {self.sender}, {self.subject}, {self.bodymessage}, {self.modules_generated}, {self.num_modules_generated}, {self.num_matches}, {self.num_lines}, {self.terminating_error}"

    def __repr__(self):
        return f"SELinuxMailMsg: {self.sender}, {self.subject}, {self.bodymessage}, {self.modules_generated}, {self.num_modules_generated}, {self.num_matches}, {self.num_lines}, {self.terminating_error}"

    def __eq__(self, other):
        return self == other

    def __ne__(self, other):
        return self != other

    def __hash__(self):
        return hash(self.bodymessage)

    def __lt__(self, other):
        return self.bodymessage < other

    def __le__(self, other):
        return self.bodymessage <= other

    def __gt__(self, other):
        return self.bodymessage > other

    def __ge__(self, other):
        return self.bodymessage >= other

    def __contains__(self, item):
        return item in self.bodymessage

    def __len__(self):
        return len(self.bodymessage)

    def __reversed__(self):
        return reversed(self.bodymessage)

    def __add__(self, other):
        return self.bodymessage + other

    def __radd__(self, other):
        return other + self.bodymessage

    def __mul__(self, other):
        return self.bodymessage * other

    def __rmul__(self, other):
        return other * self.bodymessage

    def __imul__(self, other):
        self.bodymessage *= other
        return self


class ScriptGlobals:
    """
    Class to hold global variables for the script.
    """

    def __init__(self, scriptargs: argparse.Namespace):
        self_name = f"{str(currentframe().f_code.co_name)}()"

        self.default_config = """insert_modules: false
modules_dir: ~/generated_selinux_modules
search_logfile: /var/log/messages
match_expr: '((^\w\w\w .?\d+) (\d+:\d+:\d+) (\w+).*]: (SELinux is preventing (.*) from using the (.*) capability.*?)#012#012.*ausearch -c (.*)\| audit2allow (-M.*?)#012#.*(my-.*)\.pp.*$)'
mail:
  smtpserver: 'smtpserver.domain.test'
  sender: 'semodulegen@domain.test'
  recipients:
    - sysadmins@domain.test
    - someuser@domain.test
logging:
  path: '~/.automation/python/logs'
  matches_filename: 'autogenerated_selinux_modules.yml'
"""
        self.match_template = """  - uuid: REPLACEUUID
    modulename: REPLACEMODULENAME
    logday: REPLACELOGDAY
    logtime: REPLACELOGTIME
    matchtime: REPLACEMATCHTIME
    hostname: REPLACEHOSTNAME
    process: REPLACEPROCESS
    capability: REPLACECAPABILITY
    hexdigest: REPLACEHEXDIGEST
"""
        self.args = scriptargs
        self.script_name = path.basename(sys._getframe(1).f_globals["__file__"])
        self.script_basename = self.script_name.split(".")[0]
        self.config_dir = f"~/.automation/python/config/{self.script_basename}"
        self.config_filename = f"{self.script_basename}.yml"
        self.config_file = (
            str(scriptargs.config_file[0])
            if scriptargs.config_file
            else f"{path.expanduser(self.config_dir)}/{self.config_filename}"
        )

        if not exists(path.expanduser(self.config_dir)):
            makedirs(path.expanduser(self.config_dir), exist_ok=True)
        if not exists(self.config_file):
            Path(self.config_file).touch()
            with open(file=self.config_file, mode="a", encoding="ascii") as out_file:
                out_file.write(self.default_config)
                out_file.write("\n")
            out_file.close()
            print_and_log(
                self_name,
                f"Config file did not exist. Please rerun script after customizing settings in file:\n\n {self.config_file}\n",
                settings=self,
                append_mail=False,
            )
            sys.exit(1)

        self.script_config = self.read_yaml_file(self.config_file)
        self.log_dir = f"{self.script_config.logging.path}/{self.script_basename}"
        self.insert_modules = (
            scriptargs.insert_modules
            if scriptargs.insert_modules
            else self.script_config.insert_modules
        )
        self.modules_dir = (
            str(scriptargs.modules_dir[0])
            if scriptargs.modules_dir
            else self.script_config.modules_dir
        )
        self.search_logfile = (
            str(scriptargs.search_logfile[0])
            if scriptargs.search_logfile
            else self.script_config.search_logfile
        )
        print("DEBUG: ", self.search_logfile)
        self.match_expr = (
            str(scriptargs.expression[0])
            if scriptargs.expression
            else self.script_config.match_expr
        )
        self.mail = SELinuxMailMsg(
            sender=(
                str(scriptargs.email_from[0])
                if scriptargs.email_from
                else self.script_config.mail.sender
            ),
            recipients=(
                "".join(str(scriptargs.recipients[0]).split())
                if scriptargs.recipients
                else self.script_config.mail.recipients
            ),
            smtpserver=(
                str(scriptargs.smtp_server[0])
                if scriptargs.smtp_server
                else self.script_config.mail.smtpserver
            ),
            subject=None,
            bodymessage=[],
            modules_generated=False,
            num_modules_generated=0,
            num_matches=0,
            num_lines=0,
            terminating_error=False,
        )
        self.matches_filename = self.script_config.logging.matches_filename
        self.log_filename = f"{self.script_name}.log"
        self.log_file = (
            str(scriptargs.log_file)
            if scriptargs.log_file
            else f"{path.expanduser(self.log_dir)}/{self.log_filename}"
        )
        self.matches_file = (
            str(scriptargs.generation_record)
            if scriptargs.generation_record
            else f"{path.expanduser(self.log_dir)}/{self.matches_filename}"
        )
        self.start_time = datetime.now()
        self.end_time = None
        self.yaml_digests = []
        self.selinux_matches = None
        self.hostname = os.uname().nodename
        self.create_local_files()

    def read_yaml_file(self, yaml_file: str, is_match_file: bool = False):
        """
        Reads a YAML file and returns a DotDict object. If is_match_file is
        True, does not print a message about reading the file to stdout. This
        is to prevent spamming the logfile with messages about reading the module
        generation history file.
        """
        self_name = f"{str(currentframe().f_code.co_name)}()"
        if not is_match_file:
            print_and_log(self_name, f"Attempting to read config file: {yaml_file}")
            return Config(yaml_file)
        else:
            return Config(yaml_file)

    def create_local_files(self):
        """
        Creates prerequisite local directories and config/history files if they do not exist.
        """

        if not exists(path.expanduser(self.log_dir)):
            makedirs(path.expanduser(self.log_dir), exist_ok=True)
        if not exists(path.expanduser(self.modules_dir)):
            makedirs(path.expanduser(self.modules_dir), exist_ok=True)
        if not exists(self.matches_file):
            Path(self.config_file).touch()
            with open(file=self.matches_file, mode="a", encoding="ascii") as out_file:
                out_file.write("generated_modules:\n")

        if not exists(self.log_file):
            Path(self.log_file).touch()


def find_selinux_denials(settings: ScriptGlobals):
    """
    Reads the logfile and returns a list of SELinuxMatch objects, should any lines match the regex
    'match_expr' specified in the config file.
    """
    self_name = f"{str(currentframe().f_code.co_name)}()"
    return_list = []
    return_list.append([])
    return_list.append([])
    try:
        with open(
            file=settings.search_logfile, mode="r", encoding="ascii"
        ) as in_log_file:
            i = 0
            for line in in_log_file:
                settings.mail.num_lines += 1
                log_match = re.findall(settings.match_expr, line)
                if log_match:
                    i += 1
                    settings.mail.num_matches += 1
                    match_object = SELinuxMatch(log_match, i)
                    return_list[0].append(match_object)
                    return_list[1].append(match_object.hexdigest)

    except UnicodeDecodeError as e:
        print_and_log(
            self_name,
            f"Error reading logfile (Continuing execution): {settings.search_logfile}. Exception: {exc_info()[0]}: {e}",
            settings=settings,
            log_file=settings.log_file,
        )

    except:
        print_and_log(
            self_name,
            f"Error reading logfile (Terminating error): {settings.search_logfile}",
            settings=settings,
            log_file=settings.log_file,
        )
        settings.mail.terminating_error = True
        raise

    return return_list


def append_mail_message(
    append_msg: str, settings: ScriptGlobals = None, append: bool = False
):
    """
    Just a lazy little convenience function so I don't have to
    write an 'if' statement every time a message should be appended
    to the email message body.
    """
    if append and settings is not None:
        settings.mail.bodymessage.append(append_msg)


def generate_selinux_module(selinux_match: SELinuxMatch, settings: ScriptGlobals):
    """
    Generates an SELinux module from the properties set on an SELinuxMatch object.
    Also writes out metadata about the module to a YAML file for tracking to reduce
    the probability of duplicate module generation. The uniqueness of the module is
    established by hashing the hostname, process, and capability fields of the match.
    The hash of these three fields should never be the same for two unique matches,
    and that hashed value is stored in the 'hexdigest' field of the SELinuxMatch object.
    The hexdigest field is used to determine if a module has already been generated for
    a given match, and it's also appended to the module name for easy identification.
    """

    self_name = f"{str(currentframe().f_code.co_name)}()"
    ausearch_cmd = f"ausearch -c {selinux_match.ausearch}"
    audit2allow_cmd = f"audit2allow -M {selinux_match.audit2allow}"
    dated_module_path = (
        f"{settings.modules_dir}/"
        + f"{datetime.isoformat(datetime.now())}".replace(":", ".")
    )
    if not exists(path.expanduser(dated_module_path)):
        makedirs(path.expanduser(dated_module_path), exist_ok=True)
    gen_cmd = f"/usr/bin/env bash -c 'cd {dated_module_path} && set -o pipefail && {ausearch_cmd} | {audit2allow_cmd}'"
    # Always true for debugging
    # gen_cmd = f"/usr/bin/env bash -c 'cd {dated_module_path} && set -o pipefail && find . | ls'"
    print_and_log(
        self_name,
        (
            f"Generating module:\n"
            f"Name: '{selinux_match.modulename}'\n"
            f"Match number: {selinux_match.matchnumber}\n"
            f"UUID: {selinux_match.uuid_str} \n"
            f"Day: {selinux_match.day} \n"
            f"Time: {selinux_match.time} \n"
            f"Hostname: {selinux_match.hostname} \n"
            f"Process: {selinux_match.process} \n"
            f"Capability: {selinux_match.capability} \n"
            f"Hexdigest: {selinux_match.hexdigest} \n"
            f"Command: {gen_cmd}\n"
        ),
        settings=settings,
        log_file=settings.log_file,
    )

    gen_return_code = os.system(gen_cmd)
    if gen_return_code == 0:
        settings.mail.modules_generated = True
        settings.mail.num_modules_generated += 1
        local_match_template = settings.match_template
        local_match_template = (
            local_match_template.replace("REPLACEUUID", selinux_match.uuid_str)
            .replace("REPLACEMODULENAME", selinux_match.modulename)
            .replace("REPLACELOGDAY", selinux_match.day)
            .replace("REPLACELOGTIME", selinux_match.time)
            .replace("REPLACEMATCHTIME", selinux_match.matchtime)
            .replace("REPLACEHOSTNAME", selinux_match.hostname)
            .replace("REPLACEPROCESS", selinux_match.process)
            .replace("REPLACECAPABILITY", selinux_match.capability)
            .replace("REPLACEHEXDIGEST", selinux_match.hexdigest)
        )
        with open(file=settings.matches_file, mode="a", encoding="ascii") as out_file:
            out_file.write(local_match_template)
            out_file.close()

        if settings.insert_modules:
            try:
                os.system(
                    f"semodule -X 300 -i {dated_module_path}/{selinux_match.modulename}"
                )
                print_and_log(
                    self_name,
                    f"Module {selinux_match.modulename} inserted successfully",
                    settings=settings,
                    log_file=settings.log_file,
                )
            except Exception as e:
                print_and_log(
                    self_name,
                    f"Error inserting module (Terminating error): {selinux_match.modulename}. Exception: {exc_info()[0]}: {e}",
                    settings=settings,
                    log_file=settings.log_file,
                )
                settings.mail.terminating_error = True
                raise
    else:
        print_and_log(
            self_name,
            f"Error generating module: {selinux_match.modulename}",
            settings=settings,
            log_file=settings.log_file,
        )


def send_alert_email(settings: ScriptGlobals):
    """
    Sends an alert email to the recipients specified in the config file if
    one or more SELinux modules were generated during the script's runtime.
    """
    self_name = f"{str(currentframe().f_code.co_name)}()"
    port = 587

    print_and_log(
        self_name,
        "Sending an alert email with the following details:",
        settings=settings,
        append_mail=False,
    )
    try:
        with smtplib.SMTP(host=settings.mail.smtpserver, port=port) as smtpserver:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            smtpserver.set_debuglevel(2)
            smtpserver.connect(settings.mail.smtpserver, port)
            smtpserver.ehlo()
            smtpserver.starttls(context=context)
            smtpserver.login(
                user=settings.mail.sender, password=os.getenv("SELINUX_SMTP_PASSWORD")
            )

            bodymessage = f"Out of {settings.mail.num_lines} matching lines in logfile {settings.search_logfile}, \
{settings.mail.num_matches} matches were found, {settings.mail.duplicates} of which were duplicate messages \
of modules already generated.\nThe full runtime of the script was: {settings.end_time}\n\n"

            for msg_line in settings.mail.bodymessage:
                if msg_line[len(msg_line) - 1] != "\n":
                    bodymessage += f"{msg_line}\n"
                bodymessage += f"{msg_line}\n"

            for recipient in settings.mail.recipients:
                message = MIMEText(bodymessage)
                message["Subject"] = f"{settings.mail.subject}"
                message["From"] = settings.mail.sender
                message["To"] = recipient
                print_and_log(
                    self_name,
                    f"  Subject: {settings.mail.subject}",
                    settings=settings,
                    append_mail=False,
                )
                print_and_log(
                    self_name,
                    f"  Body: {message}",
                    settings=settings,
                    append_mail=False,
                )
                print_and_log(
                    self_name,
                    f"  Recipient: {recipient}",
                    settings=settings,
                    append_mail=False,
                )
                smtpserver.sendmail(
                    settings.mail.sender, recipient, message.as_string()
                )

    except Exception as e:
        print_and_log(
            self_name,
            f"Error sending email (Terminating error): {str(e)}",
            settings=settings,
            append_mail=False,
        )
        settings.mail.terminating_error = True
        raise
