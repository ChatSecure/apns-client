# Copyright 2013 Getlogic BV, Sardar Yumatov
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import socket
import datetime
import select
from struct import pack, unpack

import OpenSSL

try:
    import json
except ImportError:
    # try some wrapper
    import omnijson as json

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading


__all__ = ('Certificate', 'Connection', 'Session', 'APNs', 'Message', 'Result')


class Certificate(object):
    """ Certificate with private key. """

    def __init__(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Provider's certificate and private key.
        
            Your certificate will probably contain the private key. Open it
            with any text editor, it should be plain text (PEM format). The
            certificate is enclosed in ``BEGIN/END CERTIFICATE`` strings and
            private key is in ``BEGIN/END RSA PRIVATE KEY`` section. If you can
            not find the private key in your .pem file, then you should
            provide it with `key_string` or `key_file` argument.

            .. note::
                If your private key is secured by a passphrase, then `pyOpenSSL`
                will query it from `stdin`. If your application is not running in
                the interactive mode, then don't protect your private key with a
                passphrase or use `passphrase` argument. The latter option is
                probably a big mistake since you expose the passphrase in your
                source code.

            :Arguments:
                - `cert_string` (str): certificate in PEM format from string.
                - `cert_file` (str): certificate in PEM format from file.
                - `key_string` (str): private key in PEM format from string.
                - `key_file` (str): private key in PEM format from file.
                - `passphrase` (str): passphrase for your private key.
        """
        self._context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv3_METHOD)
        
        if cert_file:
            # we have to load certificate for equality check. there is no
            # other way to obtain certificate from context.
            with open(cert_file, 'rb') as fp:
                cert_string = fp.read()

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
        self._context.use_certificate(cert)

        if not key_string and not key_file:
            # OpenSSL is smart enought to locate private key in certificate
            args = [OpenSSL.crypto.FILETYPE_PEM, cert_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            self._context.use_privatekey(pk)
        elif key_file and not passphrase:
            self._context.use_privatekey_file(key_file, OpenSSL.crypto.FILETYPE_PEM)
                    
        else:
            if key_file:
                # key file is provided with passphrase. context.use_privatekey_file
                # does not use passphrase, so we have to load the key file manually.
                with open(key_file, 'rb') as fp:
                    key_string = fp.read()

            args = [OpenSSL.crypto.FILETYPE_PEM, key_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            self._context.use_privatekey(pk)

        # check if we are not passed some garbage
        self._context.check_privatekey()

        # used to compare certificates.
        self._equality = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    def get_context(self):
        """ Returns SSL context instance.

            You may use that context to specify required verification level,
            trusted CA's etc.
        """
        return self._context

    def __hash__(self):
        return hash(self._equality)

    def __eq__(self, other):
        if isinstance(other, Certificate):
            return self._equality == other._equality

        return False


class Connection(object):
    """ Connection to APNs. """
    # How much of timeout to wait extra if we have some bytes from APNs, but
    # not enough for complete response. Trade-off between realtimeness and
    # not loosing response from APNs over slow network.
    extra_wait_factor = 0.5

    def __init__(self, address, certificate):
        """ Connection to APNs.

            If your application is multi-threaded, then you have to lock this
            connection before changing anything. Simply use the connection as
            context manager in ``with`` statement. 

            .. note::
                You don't have to deal with locking at all if you just use
                :class:`APNs` methods. The connection is a low-level object,
                you may use it directly if you plan to configure it to your
                needs (eg. SSL verification) or manually manage its state.

            :Arguments:
                - `address` (tuple): address as (host, port) tuple.
                - `certificate` (:class:`Certificate`): provider's certificate.
        """
        self._address = address
        self._certificate = certificate
        self._socket = None
        self._connection = None
        self._readbuf = ""
        self.__feedbackbuf = ""
        self._lock = _threading.Lock()
        self._last_refresh = None

    @property
    def address(self):
        """ Target address. """
        return self._address

    @property
    def certificate(self):
        """ Provider's certificate. """
        return self._certificate

    def is_outdated(self, delta):
        """ Returns True if this connection has not been refreshed in last delta time. """
        if self._last_refresh:
            return (datetime.datetime.now() - self._last_refresh) > delta

        return False

    def try_acquire(self):
        """ Try to lock this connection. Returns True on success, False otherwise. """
        return self._lock.acquire(False)

    def acquire(self):
        """ Lock this connection. """
        self._lock.acquire(True)

    def release(self):
        """ Unlock this connection. """
        self._lock.release()

    def __enter__(self):
        self.acquire()

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def __del__(self):
        self.close()

    def close(self):
        """ Close this connection. """
        if self._socket is not None:
            if self._connection is not None:
                try:
                    # tell SSL socket we are done
                    self._connection.shutdown()
                except:
                    pass

                try:
                    # free SSL related resources
                    self._connection.close()
                except:
                    pass

            try:
                # just to be sure. maybe we shall also call self._cocket.shutdown()
                self._socket.close()
            except:
                pass

            self._socket = None
            self._connection = None
            self._readbuf = ""
            self._feedbackbuf = ""

    def is_closed(self):
        """ Returns True if this connection is closed.

            .. note:
                If other end closes connection by itself, then this connection will
                report open until next IO operation.
        """
        return self._socket is None

    def _create_socket(self):
        """ Create new plain TCP socket. Hook that you may override. """
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def configure_socket(self):
        """ Hook to configure socket parameters. """
        pass

    def _create_openssl_connection(self):
        """ Create new OpenSSL connection. Hook that you may override. """
        return OpenSSL.SSL.Connection(self._certificate.get_context(), self._socket)

    def configure_connection(self):
        """ Hookt to configure SSL connection. """
        pass

    def _connect_and_handshake(self):
        """ Connect to APNs and SSL handshake. Hook that you may override. """
        self._connection.connect(self._address)
        self._connection.do_handshake()

    def _ensure_socket_open(self):
        """ Refreshes socket. Hook that you may override. """
        if self._socket is None:
            try:
                self._socket = self._create_socket()
                self.configure_socket()
                self._connection = self._create_openssl_connection()
                self.configure_connection()
                self._connect_and_handshake()
            except Exception:
                self.close()
                raise

    def refresh(self):
        """ Ensure socket is still alive. Reopen if needed. """
        self._ensure_socket_open()
        self._readbuf = ""
        self._feedbackbuf = ""
        self._last_refresh = datetime.datetime.now()

    def send(self, chunk):
        """ Blocking write to SSL connection.

            :Returns:
                True if chunk is fully sent, False on failure
        """
        if self.is_closed():
            return False

        # blocking mode, never throw WantWriteError
        self._connection.setblocking(1)
        try:
            self._connection.sendall(chunk)
            return True
        except OpenSSL.SSL.Error:
            # underlying connection has been closed or failed
            self.close()
            return False

    def peek(self):
        """ Non blocking read for APNs result. """
        if self.is_closed():
            return None

        ret = self.recv(256, 0)
        if not ret:
            # closed or nothing to read without blocking
            return None

        self._feed(ret)
        return self._response()

    def pull(self, timeout):
        """ Blocking read for APNs result in at most timeout. """
        if self.is_closed():
            return None

        waited = 0
        towait = timeout
        while True:
            before = time.time()
            ret = self.recv(256, towait)
            if not ret:
                # closed or timed out. possibly with some previously read, but
                # incomplete response in the buffer. we assume APNs doesn't want to
                # say anything back. This is a *really bad* protocol Apple, you suck.
                return None

            waited += time.time() - before
            self._feed(ret)
            ret = self._response()
            if ret:
                # we got response, end quickly. This usually means nothing good
                # for you, developer =)
                return ret

            # OK, we got some bytes, but it is not enough for response. should
            # never happens since we expect to get at most 6 bytes back.
            if waited >= timeout:
                # there is something in read buffer, but we run out of time.
                # that response is much more important than real-timeness, so
                # lets wait a little more.
                towait = timeout * self.extra_wait_factor
                if towait == 0:
                    # looks like subclass has disabled extra_wait_factor
                    return None
            else:
                towait = timeout - waited

    def feedback(self, buffsize, timeout):
        """ Read and parse feedback information. """
        if self.is_closed():
            return None

        data = self.recv(buffsize, timeout)
        if data is not None:
            self._feed_feedback(data)
            return self._read_feedback()

        # timeout or connection closed
        return None

    def recv(self, buffsize, timeout=None):
        """ Read bytes from connection.

            Unlike standard socket, this method returns None if other end has
            closed the connection or no data has been received within timeout.
        """
        if self.is_closed():
            return None

        if timeout is not None:
            self._connection.setblocking(0)
        else:
            self._connection.setblocking(1)

        waited = 0
        while True:
            try:
                ret = self._connection.recv(buffsize)
                if ret or timeout is None:
                    if not ret:
                        # empty result on blocking read means socket is dead.
                        # should not happen, pyOpenSSL raises WantReadError instead.
                        # but just in case we handle it.
                        self.close()

                    return ret or None
            except OpenSSL.SSL.ZeroReturnError:
                # SSL protocol alerted close. We have a nice shutdown here.
                self.close()
                return None
            except OpenSSL.SSL.WantReadError:
                # blocking mode and there is not enough bytes read means socket
                # is abruptly closed (other end crashed)
                if timeout is None:
                    self.close()
                    return None

            if timeout == 0 or waited >= timeout:
                # no time left
                return None

            # so, we perform blocking read and there was not enough bytes.
            # note: errors is for out-of-band and other shit. not what you may
            # think an IO erro would be ;-)
            before = time.time()
            canread, _, _ = select.select((self._socket, ), (), (), timeout - waited)
            if not canread:
                # timeout elapsed without data becoming available, bail out
                return None

            waited += time.time() - before

    def _feed(self, data):
        self._readbuf += data

    def _response(self):
        if len(self._readbuf) >= 6:
            ret = unpack(">BBI", self._readbuf[0:6])
            self._readbuf = self._readbuf[6:]

            if ret[0] != 8:
                raise ValueError("Got unknown command from APNs. Looks like protocol has been changed.")

            return (ret[1], ret[2])

        return None

    def _feed_feedback(self, data):
        self._feedbackbuf += data

    def _read_feedback(self):
        # FIXME: not the most efficient way to parse stream =)
        while len(self._feedbackbuf) > 6:
            timestamp, length = unpack(">IH", self._feedbackbuf[0:6])
            if len(self._feedbackbuf) >= (6 + length):
                token = self._feedbackbuf[6:(length + 6)].encode("hex").upper()
                self._feedbackbuf = self._feedbackbuf[(length + 6):]
                yield (token, timestamp)
            else:
                break


class Session(object):
    """ Persistent connection pool. """
    # Connection wrapper class to use
    connection_class = Connection

    # Default APNs addresses.
    ADDRESSES = {
        "push_sandbox": ("gateway.sandbox.push.apple.com", 2195),
        "push_production": ("gateway.push.apple.com", 2195),
        "feedback_sandbox": ("feedback.sandbox.push.apple.com", 2196),
        "feedback_production": ("feedback.push.apple.com", 2196),
    }
    
    def __init__(self):
        """ Persistent connection pool.

            It is a good idea to keep your connection open to APNs if you
            expect to send another message within few minutes. SSL hanshaking
            is slow, so preserving a connection will increase your message
            throughput.
            
            This class keeps connection descriptors for you, but it is your
            responsibility to keep reference to session instances, otherwise
            the session will be garbage collected and all connections will be
            closed.
        """
        self._connections = {}

    @classmethod
    def new_connection(cls, address="feedback_sandbox", certificate=None, **cert_params):
        """ Obtain non-cached connection to APNs.
            
            Unlike :func:`get_connection` this method does not cache the
            connection.  Use it to fetch feedback from APNs and then close when
            you are done.

            :Arguments:
                - `address` (str or tuple): target address.
                - `certificate` (:class:`Certificate`): provider's certificate instance.
                - `cert_params` (kwargs): :class:`Certificate` arguments, used if `certificate` instance is not given.
        """
        if isinstance(address, basestring):
            addr = cls.ADDRESSES.get(address)
            if addr is None:
                raise ValueError("Unknown address mapping: {0}".format(address))

            address = addr

        if certificate is not None:
            cert = certificate
        else:
            cert = Certificate(**cert_params)

        return cls.connection_class(address, cert)

    def get_connection(self, address="push_sanbox", certificate=None, **cert_params):
        """ Obtain cached connection to APNs.

            Session caches connection descriptors, that remain open after use.
            Caching saves SSL handshaking time. Handshaking is lazy, it will be
            performed on first message send.

            You can provide APNs address as ``(hostname, port)`` tuple or as
            one of the strings:

                - `push_sanbox` -- ``("gateway.sandbox.push.apple.com", 2195)``, the default.
                - `push_production` -- ``("gateway.push.apple.com", 2195)``
                - `feedback_sandbox` -- ``("gateway.push.apple.com", 2196)``
                - `feedback_production` -- ``("gateway.sandbox.push.apple.com", 2196)``

            :Arguments:
                - `address` (str or tuple): target address.
                - `certificate` (:class:`Certificate`): provider's certificate instance.
                - `cert_params` (kwargs): :class:`Certificate` arguments, used if `certificate` instance is not given.
        """
        if isinstance(address, basestring):
            addr = self.ADDRESSES.get(address)
            if addr is None:
                raise ValueError("Unknown address mapping: {0}".format(address))

            address = addr

        if certificate is not None:
            cert = certificate
        else:
            cert = Certificate(**cert_params)

        key = (address, cert)
        if key not in self._connections:
            self._connections[key] = self.connection_class(address, cert)

        return self._connections[key]

    def outdate(self, delta):
        """ Close open connections that are not used in more than ``delta`` time.

            You may call this method in a separate thread or run it in some
            periodic task. If you don't, then all connections will remain open
            until session is shut down. It might be an issue if you care about
            your open server connections.

            :Arguments:
                `delta` (``timedelta``): maximum age of unused connection.

            :Returns:
                Number of closed connections.
        """
        # no need to lock _connections, Python GIL will ensures exclusive access
        to_check = self._connections.values()

        # any new connection added to _connections in parallel are assumed to be
        # within delta.
        ret = 0
        for con in to_check:
            if con.try_acquire():
                try:
                    if not con.is_closed() and con.is_outdated(delta):
                        con.close()
                        ret += 1
                finally:
                    con.release()

        return ret

    def shutdown(self):
        """ Shutdown all connections.

            Method iterates over all connections ever used and closes them one
            by one. If connection is in use, then method will wait until consumer
            is finished.
        """
        to_check = self._connections.values()
        for con in to_check:
            try:
                with con:
                    con.close()
            except:
                pass

    def __del__(self):
        """ Last chance to shutdown() """
        self.shutdown()


class APNs(object):
    """ APNs multicaster. """

    def __init__(self, connection, packet_size=2048, tail_timeout=0.5):
        """ APNs client.

            It is a good idea to keep your ``packet_size`` close to MTU for
            better networking performance. However, if packet fails without
            any feedback from APNs, then all device tokens in the packet will
            be considered to have failed.

            The ``tail_timeout`` argument defines timeouts for all networking
            operations. APNs protocol does not define a *success* message, so
            in order to be sure the batch was successfully processed, we have
            to wait for any response at the end of :func:`send`. So, any send
            will take time needed for sending everything plus ``tail_timeout``.
            Blame Apple for this.
        
            :Arguments:
                - `connection` (:class:`Connection`): the connection to talk to.
                - `packet_size` (int): minimum size of IO buffer in bytes.
                - `tail_timeout` (float): timeout for final read in seconds.
        """
        self._connection = connection
        self.packet_size = packet_size
        self.tail_timeout = tail_timeout

    def send(self, message):
        """ Send the message.
        
            The method will block until the whole message is sent. Method returns
            :class:`Result` object, which you can examine for possible errors and
            retry attempts.

            :Returns:
                :class:`Result` object with operation results.
        """
        with self._connection:
            # ensure connection is up, may raise all kinds of exceptions
            self._connection.refresh()

            # serialize to binary in chunks of packet_size. Choose packet_size large
            # enough for good networking performance.
            batch = message.batch(self.packet_size)
            failed_after = None
            for sent, chunk in batch:
                # blocking write
                if not self._connection.send(chunk):  # may fail on IO
                    # socket is closed, check what happened
                    failed_after = sent
                    break

                # non-blocking read
                ret = self._connection.peek()
                if ret is not None and ret[0] != 0:
                    # some shit had happened, response from APNs, bail out and prepare for retry
                    self._connection.close()
                    return Result(message, ret)

            # blocking read for at most tail_timeout
            ret = self._connection.pull(self.tail_timeout)
            if ret is not None and ret[0] != 0:
                # some shit had indeed happened
                self._connection.close()
                return Result(message, ret)

            # OK, we have nothing received from APNs, but maybe this is due to timeout.
            # Check if we were abrubtly stopped because connection was closed
            if failed_after is not None:
                # unknown error happened, we assume everything after last successful
                # send can be retried. It does not hurt to ensure/close again.
                self._connection.close()
                ret = (255, failed_after + 1)
                return Result(message, ret)

            # we have sent message to all target tokens and have waited for
            # tail_timeout for any error reponse to arrive. Nothing arrived and
            # we did not fail middle on the road, so according to Apple's
            # manual everything went OK. Still, this protocol sucks.
            return Result(message)

    def feedback(self):
        """ Fetch feedback from APNs.

            The method returns generator of ``(token, datetime)`` pairs,
            denoting the timestamp when APNs has detected the device token is
            not available anymore, probably because application was
            uninstalled. You have to stop sending notifications to that device
            token unless it has been re-registered since reported timestamp.
            
            Unlike sending the message, you should fetch the feedback using
            non-cached connection. Once whole feedback has been read, this
            method will automatically close the connection.

            .. note::
                On any IO/SSL error this method will simply stop iterating and
                will close the connection. There is nothing you can do in case
                of an error. Just let it fail, next time yo uwill fetch the
                rest of the failed tokens.

            Example::

                con = Session.new_connection("feedback_production", cert_string=db_certificate)
                service = APNs(con, tail_timeout=10)
                for token, when in service.feedback():
                    print "Removing token ", token

            :Returns:
                generator over ``(str, datetime.datetime)``
        """
        # FIXME: this library is not idiot proof. If you store returned generator
        # somewhere, then yes, the connection will remain locked.
        with self._connection:
            # ensure connection is up, may raise all kinds of exceptions
            self._connection.refresh()
            while True:
                items = self._connection.feedback(self.packet_size, self.tail_timeout)
                if items is not None:
                    for token, timestamp in items:
                        yield (token, datetime.datetime.fromtimestamp(timestamp))
                else:
                    # a timeout or failure or socket was closed.
                    break


class Message(object):
    """ The notification message. """
    # JSON serialization parameters. Assume UTF-8 by default.
    json_parameters = {
        'separators': (',',':'),
        'ensure_ascii': False,
    }

    def __init__(self, tokens, alert=None, badge=None, sound=None, expiry=None, payload=None, **extra):
        """ The push notification to one or more device tokens.

            Read more `about payload
            <http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW9>`_.

            :Arguments:
                - `tokens` (str or list): set of device tokens where to message will be sent.
                - `alert` (str or dict): the message; read APNs manual for recognized dict keys (localized messages).
                - `badge` (int or str): badge number over the application icon or "
                - `sound` (str): sound file to play on arrival.
                - `expiry` (int or datetime or timedelta): timestamp when message will expire
                - `payload` (dict): JSON-compatible dictionary with the
                                    complete message payload. If supplied, it
                                    is given instead of all the other, more
                                    specific parameters.
                - `extra` (kwargs): extra payload key-value pairs.
        """
        if (payload is not None and (
                alert is not None or badge is not None or sound is not None or extra)):
            # Raise an error if both `payload` and the more specific
            # parameters are supplied.
            raise ValueError("Payload specified together with alert/badge/sound/extra.")

        if isinstance(tokens, basestring):
            tokens = [tokens]

        self._tokens = tokens
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.extra = extra
        self._payload = payload

        if expiry is None:
            # 0 means do not store messages at all. so we have to choose default
            # expiry, which is here 1 day.
            expiry = datetime.timedelta(days=1)

        if isinstance(expiry, datetime.timedelta):
            expiry = datetime.datetime.now() + expiry

        if isinstance(expiry, datetime.datetime):
            expiry = time.mktime(expiry.timetuple())

        self.expiry = int(expiry)

        if 'aps' in self.extra:
            raise ValueError("Extra payload data may not contain 'aps' key.")

    def __getstate__(self):
        """ Returns ``dict`` with ``__init__`` arguments.

            If you use ``pickle``, then simply pickle/unpickle the message object.
            If you use something else, like JSON, then::
                
                # obtain state dict from message
                state = message.__getstate__()
                # send/store the state
                # recover state and restore message
                message_copy = Message(**state)

            .. note::
                The message keeps ``expiry`` internally as a timestamp
                (integer).  So, if values of all other arguments are JSON
                serializable, then the returned state must be JSON
                serializable.  If you get ``TypeError`` when you instantiate
                ``Message`` from JSON recovered state, then make sure the keys
                are ``str``, not ``unicode``.

            :Returns:
                `kwargs` for `Message` constructor.
        """
        if self._payload is not None:
            return {'payload': self._payload}

        ret = dict((key, getattr(self, key)) for key in ('tokens', 'alert', 'badge', 'sound', 'expiry'))
        if self.extra:
            ret.update(self.extra)

        return ret
    
    def __setstate__(self, state):
        """ Overwrite message state with given kwargs. """
        self._tokens = state['tokens']
        self.extra = {}
        self.expiry = state['expiry']

        if 'payload' in state:
            self._payload = state['payload']
            self.alert = None
            self.badge = None
            self.sound = None
        else:
            self._payload = None
            for key, val in state.iteritems():
                if key in ('tokens', 'expiry'): # already set
                    pass
                elif key in ('alert', 'badge', 'sound'):
                    setattr(self, key, state[key])
                else:
                    self.extra[key] = val

    @property
    def tokens(self):
        """ List target device tokens. """
        return self._tokens

    @property
    def payload(self):
        """ Returns the payload content as a `dict`. """
        if self._payload is not None:
            return self._payload
        
        aps = {
            # XXX: we do not check alert, which could be string or dict with extra options
            'alert': self.alert
        }

        if self.badge is not None:
            aps['badge'] = self.badge

        if self.sound is not None:
            aps['sound'] = str(self.sound)

        ret = {
            'aps': aps,
        }
        
        if self.extra:
            ret.update(self.extra)

        return ret

    def get_json_payload(self):
        """ Convert message to JSON payload, acceptable by APNs. Must return byte string. """
        ret = json.dumps(self.payload, **self.json_parameters)
        if isinstance(ret, basestring):
            ret = ret.encode("utf-8")

        return ret

    def batch(self, packet_size):
        """ Returns binary serializer. """
        payload = self.get_json_payload()
        return Batch(self._tokens, payload, self.expiry, packet_size)

    def retry(self, failed_index, include_failed):
        """ Create new retry message with tokens from failed index. """
        if not include_failed:
            failed_index += 1

        failed = self._tokens[failed_index:]
        if not failed:
            # nothing to retry
            return None

        return Message(failed, self.alert, badge=self.badge, sound=self.sound, expiry=self.expiry, **self.extra)


class Batch(object):
    """ Binary stream serializer. """

    def __init__(self, tokens, payload, expiry, packet_size):
        """ New serializer.

            :Arguments:
                - `tokens` (list): list of target target device tokens.
                - `payload` (str): JSON payload.
                - `expiry` (int): expiry timestamp.
                - `packet_size` (int): minimum chunk size in bytes.
        """
        self.tokens = tokens
        self.payload = payload
        self.expiry = expiry
        self.packet_size = packet_size
        
    def __iter__(self):
        """ Iterate over serialized chunks. """
        messages = []
        buf = 0
        sent = 0

        # for all registration ids
        for idx, token in enumerate(self.tokens):
            tok = token.decode("hex")
            # |COMMAND|ID|EXPIRY|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD|
            fmt = ">BIIH%ssH%ss" % (len(tok), len(self.payload))
            message = pack(fmt, 1, idx, self.expiry, len(tok), tok, len(self.payload), self.payload)
            messages.append(message)
            buf += len(message)
            if buf > self.packet_size:
                chunk = "".join(messages)
                buf = 0
                prev_sent = sent
                sent += len(messages)
                messages = []
                yield prev_sent, chunk

        # last small chunk
        if messages:
            yield sent, "".join(messages)


class Result(object):
    """ Result of send operation. """
    # all rerror codes {code: (explanation, can retry?, include failed token?)}
    ERROR_CODES = {
        1: ('Processing error', True, True),
        2: ('Missing device token', True, False), # looks like token was empty?
        3: ('Missing topic', False, True), # topic is encoded in the certificate, looks like certificate is wrong. bail out.
        4: ('Missing payload', False, True), # bail out, our message looks like empty
        5: ('Invalid token size', True, False), # current token has wrong size, skip it and retry
        6: ('Invalid topic size', False, True), # can not happen, we do not send topic, it is part of certificate. bail out.
        7: ('Invalid payload size', False, True), # our payload is probably too big. bail out.
        8: ('Invalid token', True, False), # our device token is broken, skipt it and retry
        None: ('Unknown', True, True), # unknown error, for sure we try again, but user should limit number of retries
    }

    def __init__(self, message, failure=None):
        """ Result of send operation. """
        self.message = message
        self._retry_message = None
        self._failed = {}
        self._errors = []

        if failure is not None:
            reason, failed_index = failure
            if reason not in self.ERROR_CODES:
                # one of "unknown" error codes
                reason = None

            expl, can_retry, include_failed = self.ERROR_CODES[reason]
            if can_retry:
                # may be None if failed on last token, which is skipped
                self._retry_message = message.retry(failed_index, include_failed)

            if not include_failed: # report broken token, it was skipped
                self._failed = {
                    message.tokens[failed_index]: (reason, expl)
                }
            else: # errors not related to broken token, global shit happened
                self._errors = [
                    (reason, expl)
                ]

    @property
    def errors(self):
        """ Returns list of ``(reason, explanation)`` pairs denoting severe errors,
            not related to failed tokens. The reason is an integer code as
            described in APNs tutorial.

            The following codes are considered to be errors:
                - ``(1, "Processing error")``
                - ``(3, "Missing topic")``
                - ``(4, "Missing payload")``
                - ``(6, "Invalid topic size")``
                - ``(7, "Invalid payload size")``
                - ``(None, "Unknown")``
        """
        return self._errors

    @property
    def failed(self):
        """ Reports failed tokens as ``{token : (reason, explanation)}`` mapping.

            Current APNs protocols bails out on first failed device token, so
            the returned dict will contain at most 1 entry. Future extensions
            may upgrade to multiple failures in a batch. The reason is the
            integer code as described in APNs tutorial.

            The following codes are considered to be token failures:
                - ``(2, "Missing device token")``
                - ``(5, "Invalid token size")``
                - ``(8, "Invalid token")``
        """
        return self._failed

    def needs_retry(self):
        """ Returns True if there are tokens that could be retried. """
        return self._retry_message is not None

    def retry(self):
        """ Returns :class:`Message` with device tokens that can be retried.
       
            Current APNs protocol bails out on first failure, so any device
            token after the failure should be retried. If failure was related
            to the token, then it will appear in :attr:`failed` set and will be
            in most cases skipped by the retry message.
        """
        return self._retry_message
