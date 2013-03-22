apns-client.
====================================
Python client for `Apple Push Notification service (APNs) <http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html>`_.
Check `documentation <http://apns-client.readthedocs.org>`_ to learn how to use it.

Check the client with similar interface for `Google Cloud Messaging <https://pypi.python.org/pypi/gcm-client/>`_.


Requirements
------------

- `pyOpenSSL <https://pypi.python.org/pypi/pyOpenSSL>`_ - OpenSSL wrapper.
- `omnijson <https://pypi.python.org/pypi/omnijson/>`_ if you use Python 2.5 or older.

Standard library has support for `SSL transport
<http://docs.python.org/2/library/ssl.html>`_. However, it is impossible to use
it with certificates provided as a string. We store certificates in database,
because we handle different apps on many Celery worker machines.  A dirty
solution would be to create temporary files, but it is insecure and slow. So,
we have decided to use a better OpenSSL wrapper and ``pyOpenSSL`` was the
easiest to handle.


Alternatives
------------

There are `many alternatives
<https://pypi.python.org/pypi?%3Aaction=search&term=apns&submit=search>`_
available. We have started with `pyapns <https://pypi.python.org/pypi/pyapns>`_
and `APNSWrapper <https://pypi.python.org/pypi/APNSWrapper>`_. This library
differs in the following design decisions:

- *Support certificates from strings*. We do not distribute certificate files
  on worker machines, they fetch it from the database when needed. This
  approach simplifies deployment, upgrades and maintenance.
- *Keep connections persistent*. An SSL handshaking round is slow. Once
  connection is established, it should remain open for at least few minutes,
  waiting for the next batch.
- *Support enhanced format*. Apple developers have designed a notoriously bad
  push protocol. They have upgraded it to enhanced version, which makes it
  possible to detect which messages in the batch have failed.
- *Clean pythonic API*. No need for lots of classes, long lists of exceptions etc.
- *Do not hard-code validation, let APNs fail*. This decision makes library
  a little bit more future proof.

Support
-------
APNs client was created by `Sardar Yumatov <mailto:ja.doma@gmail.com>`_,
contact me if you find any bugs or need help. Contact `Getlogic
<http://getlogic.nl>`_ if you need a full-featured push notification service
for all popular platforms. You can view outstanding issues on the `APNs
Bitbucket page <https://bitbucket.org/sardarnl/apns-client/>`_.
