#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import atexit
import logging
from typing import Dict

from pypsexec.client import Client  # https://github.com/jborean93/pypsexec
from pypsexec.exceptions import SCMRException
from smbprotocol.exceptions import SMBAuthenticationError

_LOGGER = logging.getLogger(__name__)


class PSExecAPI(object):
    _cache = {}  # type: Dict[PSExecAPI]

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self._session_id = None  # type: int or None
        self.timeout = 10
        self.__client = None  # Client or None
        self._register_at_exit()

    def __str__(self):
        return "%s%s:%s@%s" % (__name__, self.username, self.password, self.hostname)

    @property
    def session_established(self):
        return self._client and hasattr(self._client, 'session')

    @staticmethod
    def _clear_all():
        PSExecAPI._cache.clear()

    @classmethod
    def get(cls, hostname, username, password):
        # noinspection PyTypeChecker
        output = PSExecAPI._cache.get((hostname, username, password))
        if output is None:
            output = cls(hostname, username, password)
        return output

    @staticmethod
    def _remove_class_cache(class_):
        _key = (class_.hostname, class_.username, class_.password)
        if _key in PSExecAPI._cache:
            # noinspection PyTypeChecker
            PSExecAPI._remove_cache(*_key)

    # noinspection PyTypeChecker
    @staticmethod
    def _remove_cache(hostname, username, password):
        key = (hostname, username, password)
        if key in PSExecAPI._cache.keys():
            # noinspection PyProtectedMember
            PSExecAPI._cache[key]._disconnect()
            PSExecAPI._cache.pop(key)

    @property
    def _client(self):
        # type: () -> Client or None
        if self.__client is None:
            self.__client = Client(self.hostname, self.username, self.password)
            _LOGGER.info('Establishing PSExec connection with %s@%s with timeout %s seconds ... ' % (
                self.username, self.hostname, self.timeout))
            # Remote Host Requirements: https://github.com/jborean93/pypsexec#remote-host-requirements
            # try:
            #     self.__client.connect(timeout=self.timeout)
            #     self.__client.cleanup()
            #     self.__client.disconnect()
            # except:
            #     pass

            try:
                self.__client.connect(timeout=self.timeout)
                self.__client.create_service()
            except SMBAuthenticationError as e:
                _LOGGER.error("%s Authentication Error: %s %s" % (__name__, type(e), e))
                self._destroy()
                return
            except SCMRException as e:
                _LOGGER.error("%s SCMRException Exception: %s %s" % (__name__, type(e), e))
            except Exception as e:
                _LOGGER.error("%s Exception: %s %s" % (__name__, type(e), e))
                self._destroy()
                return

            # noinspection PyTypeChecker
            PSExecAPI._cache[(self.hostname, self.username, self.password)] = self
        return self.__client

    def _destroy(self):
        self._disconnect()
        self.__client = None
        PSExecAPI._remove_class_cache(self)

    def _cleanup(self):
        try:
            self.__client.cleanup()
        except:
            pass

    def _disconnect(self):
        if not self.__client:
            return

        try:
            self.__client.remove_service()
            self.__client.disconnect()
        except:
            pass

    def _register_at_exit(self):
        atexit.register(self._disconnect)

    def run_cmd(self, cmd, interactively=False, asynchronous=False, session_id=None, use_system_account=True, **kwargs):
        if interactively:
            return self.run_interactively('cmd', arguments='/c "%s"' % cmd, asynchronous=asynchronous,
                                          session_id=session_id, use_system_account=use_system_account, **kwargs)

        return self.run_executable('cmd', arguments='/c "%s"' % cmd, interactive_session=session_id, **kwargs)

    def run_executable(self, executable, **kwargs):
        _LOGGER.debug("Running remote executable @ {s.username}@{s.hostname}: {exe} {kw}".format(
            s=self, exe=executable, kw=kwargs if kwargs else ''))
        if not self._client:
            _LOGGER.warning(
                "Cannot run executable: connection not established @ %s@%s" % (self.username, self.hostname))
            return

        _LOGGER.info("Running executable %s" % executable)
        stdout, stderr, return_code = self._client.run_executable(executable, **kwargs)
        _stderr_str = 'Stderr:\n%s\n\n' % stderr.strip() if stderr and stderr.strip() else ''
        _stdout_str = 'Stdout:\n%s\n\n' % stdout.strip() if stdout and stdout.strip() else ''
        _LOGGER.debug("%s%sReturn Code: %s" % (_stderr_str, _stdout_str, return_code))
        return stdout, stderr, return_code

    def run_interactively(self, executable, arguments=None, asynchronous=False, session_id=None,
                          use_system_account=True, **kwargs):
        session_id = session_id or self.session_id
        if not session_id:
            _LOGGER.warning("Cannot run %s interactively: User not logged in" % executable)
            return

        kwargs.update({'interactive': True, 'interactive_session': session_id, 'use_system_account': use_system_account,
                       'asynchronous': asynchronous})
        _LOGGER.info("Running %s interactively" % executable)
        return self.run_executable(executable, arguments=arguments, **kwargs)

    def mirror_folder(self, remote_folder, local_folder, multi_thread=True, **kwargs):
        _multi_thread = '/MT' if multi_thread else ''
        _args = '"%s" "%s" /UNICODE /MIR %s' % (remote_folder, local_folder, _multi_thread)
        kwargs.update({'arguments': _args})
        _LOGGER.info("Mirroring folders %s and %s" % (remote_folder, local_folder))
        output = self.run_executable('robocopy.exe', **kwargs)
        stdout, stderr, return_code = output if output else (None, None, None)
        return stdout, stderr, return_code

    def get_session_id(self, user=None):
        user = user or self.username
        _LOGGER.debug("Getting session ID for %s@%s" % (user, self.hostname))
        _args = '/c tasklist /NH /FI "USERNAME eq %s" /FI "IMAGENAME eq RuntimeBroker.exe"' % user
        stdout, stderr, return_code = self._client.run_executable('cmd', arguments=_args, use_system_account=False)
        _LOGGER.debug("Get Session ID STDOUT: %s" % stdout)
        _LOGGER.debug("Get Session ID STDERR: %s" % stderr)
        _LOGGER.debug("Get Session ID return_code: %s" % return_code)
        if stderr and str(stderr).strip():
            _LOGGER.warning("Error getting session ID for %s@%s. User is not logged in?" % (user, self.hostname))
            return

        if stdout and "INFO: No tasks are running which match the specified criteria." in str(stdout).strip():
            _LOGGER.warning("Couldn't get Session ID for %s@%s. User is not logged in" % (user, self.hostname))
            return

        if not stdout or not str(stdout).strip():
            _LOGGER.warning("Couldn't get Session ID for %s@%s. Stdout empty?\n%s" % (user, self.hostname, stdout))
            return

        brokers_split = str(stdout).strip().split('\n')
        if not brokers_split:
            _LOGGER.warning(
                "Couldn't get Session ID for %s@%s. Brokers list empty?\n%s" % (user, self.hostname, stdout))
            return

        broker = brokers_split[0].split()
        if len(broker) < 3:
            _LOGGER.warning(
                "Couldn't get Session ID for %s@%s. Broker split empty?\n%s" % (user, self.hostname, broker))
            return

        session_id = broker[3]
        _LOGGER.debug("Got session id: %s" % session_id)

        try:
            output = int(session_id)
        except:
            _LOGGER.warning("Error parsing session ID for %s@%s: %s" % (user, self.hostname, str(stdout).strip()))
            return

        _LOGGER.info("Got session ID for %s@%s: %s" % (user, self.hostname, output))
        return output

    @property
    def session_id(self):
        if self._session_id is None:
            if not self._client:
                _LOGGER.warning("Couldn't get session id: client is None")
                return

            self._session_id = self.get_session_id()
        return self._session_id

    def check_file_exists(self, file_path):
        output = self.run_executable('cmd.exe', arguments='/c where "%s"' % file_path)
        if output is None:
            return

        stdout, stderr, return_code = output
        if stderr is None or stderr.strip() or stdout is None or not stdout.strip():
            _LOGGER.warning("Couldn't check_file_exists %s " % file_path)
            return

        if "Could not find files for the given pattern" in str(stdout):
            return False

        return stdout.strip()

    def check_install_choco(self):
        choco = self.check_file_exists('choco.exe')
        if not choco:
            self.install_choco()

    def install_choco(self, interactively=False, asynchronous=False, session_id=None):
        return self.run_cmd("powershell Set-ExecutionPolicy Bypass -Scope Process -Force; "
                            "iex ((New-Object System.Net.WebClient)."
                            "DownloadString('https://chocolatey.org/install.ps1'))"
                            "&refreshenv"
                            "&choco feature enable -n=allowGlobalConfirmation -y"
                            "&choco feature disable -n=ignoreInvalidOptionsSwitches -y"
                            "&choco feature enable -n=usePackageExitCodes -y"
                            "&choco feature disable -n=showNonElevatedWarnings -y",
                            interactively=interactively, asynchronous=asynchronous, session_id=session_id)

    def install_choco_module(self, module_name):
        self.check_install_choco()
        return self.run_cmd('cinst %s' % module_name)

    def create_shortcut(self, target, location="~$folder.desktop$", title='My Shortcut', arguments='',
                        icon_path="", icon_number=0, run_as=""):
        """
        https://nircmd.nirsoft.net/shortcut.html
        """
        return self.run_cmd('nircmd shortcut "{target}" "{location}" "{title}" "{arguments}" '
                            '"{icon_path}" {icon_number} "{run_as}"'.format(target=target, location=location,
                                                                            title=title, arguments=arguments,
                                                                            icon_path=icon_path,
                                                                            icon_number=icon_number, run_as=run_as))


def main():
    psexec = PSExecAPI.get('192.168.1.2', 'alexe', 'tGCqif9!')
    exists = psexec.check_file_exists('explorer.exe')
    ex = psexec.run_cmd('nircmd speak text "blabla"', interactively=True)
    psexec.run_cmd('nircmd.exe speak text "text" 0 50')
    psexec.run_cmd('nircmd.exe speak text "text" 0 50')
    pass


if __name__ == '__main__':
    main()
    print("")
