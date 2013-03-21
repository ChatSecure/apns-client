gcm-client
==========
Python client for `Google Cloud Messaging (GCM) <http://developer.android.com/google/gcm/index.html>`_.

Requirements
------------

- `requests <http://docs.python-requests.org>`_ - HTTP request, handles proxies etc.
- `omnijson <https://pypi.python.org/pypi/omnijson/>`_ if you use Python 2.5 or older.

Alternatives
------------
Th only alternative library known at the time of writing was `python-gcm
<https://pypi.python.org/pypi/python-gcm>`_.  This library differs in the
following design decisions:

- *Predictable execution time*. Do not automatically retry request on failure.
  According to Google's recommendations, each retry has to wait exponential
  back-off delay. We use Celery back-end, where the best way to retry after
  some delay will be scheduling the task with ``countdown=delay``.  Sleeping
  while in Celery worker hurts your concurrency.
- *Do not forget results if you need to retry*. This sounds obvious, but
  ``python-gcm`` drops important results, such as canonical ID mapping if
  request needs to be (partially) retried.
- *Clean pythonic API*. No need to borrow all Java like exceptions etc.
- *Do not hard-code validation, let GCM fail*. This decision makes library
  a little bit more future proof.

Support
-------
GCM client was created by `Sardar Yumatov <mailto:ja.doma@gmail.com>`_, contact
me if you find any bugs or need help. You can view outstanding issues on the
`GCM Bitbucket page <https://bitbucket.org/sardarnl/gcm-client/>`_.

Usage
-----
`Read documentation <http://gcm-client.readthedocs.org/>`_ for more info.

Usage is straightforward::

    from gcmclient import *

    # You have to obtain Google API Key from developers console.
    # You work through a proxy? Pass 'proxies' keyword argument, as described
    # in 'requests' library. Check of other options too.
    gcm = GCM(API_KEY)

    # construct (key => scalar) payload. do not use nested structures.
    data = {'str': 'string', 'int': 10}

    # unicast or multicast message, read GCM manual about extra options.
    unicast = PlainTextMessage("registration_id", data, dry_run=True)
    multicast = JSONMessage(["registration_id_1", "registration_id_2"],
                             data,
                             collapse_key='my.key',
                             dry_run=True)

    try:
        # attempt send
        res_unicast = gcm.send(unicast)
        res_multicast = gcm.send(multicast)

        for res in [res_unicast, res_multicast]:
            # nothing to do on success
            for reg_id, msg_id in res.success.items():
                print "Successfully sent %s as %s" % (reg_id, msg_id)

            # update your registration ID's
            for reg_id, new_reg_id res.canonical.items():
                print "Replacing %s with %s in database" % (reg_id, new_reg_id)

            # probably app was uninstalled
            for reg_id in res.not_registered:
                print "Removing %s from database" % reg_id

            # unrecoverably failed, these ID's will not be retried
            for reg_id, err_code in res.failed.items():
                print "Removing %s because %s" % (reg_id, err_code)

            # if some registration ID's have recoverably failed
            if res.needs_retry():
                # construct new message with only failed regids
                retry_msg = res.retry()
                # you have to wait before attemting again. delay()
                # will tell you how long to wait depending on your
                # current retry counter, starting from 0.
                print "Wait or schedule task after %s seconds" % res.delay(retry)
                # retry += 1 and send retry_msg again

    catch GCMAuthenticationError:
        # stop and fix your settings
        print "Your Google API key is rejected"
    catch ValueError, e:
        # probably your extra options, such as time_to_live,
        # are invalid. Read error message for more info.
        print "Invalid message/option or invalid GCM response"
        print e.args[0]
    catch Exception:
        # your network is down or maybe proxy settings
        # are broken. when problem is resolved, you can
        # retry the whole message.
        print "Something wrong with requests library"

