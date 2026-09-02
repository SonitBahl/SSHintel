import paramiko
import threading
from .logger import creds_logger, funnel_logger, log_event

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None, session_id=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.session_id = session_id
        self.auth_username = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.auth_username = username
        # Preserve the original v1.0 credential attempt log.
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        # Structured telemetry. The password is captured deliberately because
        # the honeypot already records credential attempts.
        log_event(
            'auth_attempt',
            session_id=self.session_id,
            source_ip=self.client_ip,
            username=username,
            auth_method='password',
            password=password,
        )
        if self.input_username and self.input_password:
            if username == self.input_username and password == self.input_password:
                log_event(
                    'auth_success',
                    session_id=self.session_id,
                    source_ip=self.client_ip,
                    username=username,
                )
                return paramiko.AUTH_SUCCESSFUL
            log_event(
                'auth_failure',
                session_id=self.session_id,
                source_ip=self.client_ip,
                username=username,
            )
            return paramiko.AUTH_FAILED
        # Accept-all mode: no credentials were configured, so any attempt is
        # accepted (v1.0 behaviour preserved).
        log_event(
            'auth_success',
            session_id=self.session_id,
            source_ip=self.client_ip,
            username=username,
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True