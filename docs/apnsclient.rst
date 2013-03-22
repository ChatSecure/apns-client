apnsclient Package
==================
`Apple Push Notification service
<http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Introduction/Introduction.html#//apple_ref/doc/uid/TP40008194-CH1-SW1>`_
client. Only public API is documented here to limit visual clutter. Refer to
`the sources <https://bitbucket.org/sardarnl/apns-client/>`_ if you want to
extend this library. Check :ref:`intro` for usage examples.


:mod:`apnsclient` Package
-------------------------


.. automodule:: apnsclient.apns

.. autoclass:: Session
    :members: new_connection, get_connection, outdate, shutdown

.. autoclass:: APNs
    :members: send, feedback

.. autoclass:: Message
    :members: tokens

.. autoclass:: Result
    :members: errors, failed, needs_retry, retry

.. autoclass:: Certificate
    :members: get_context

.. autoclass:: Connection
    :members: address, certificate, close, is_closed, refresh
