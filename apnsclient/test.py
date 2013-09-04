if __name__ == '__main__':
    import os.path, sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import unittest, struct, pickle, json
import time
import datetime
from mock import patch
from OpenSSL.SSL import ZeroReturnError

from apnsclient import *



class APNsTest(unittest.TestCase):
    """ Test APNs client. """

    @patch('OpenSSL.SSL')
    @patch('OpenSSL.crypto')
    def setUp(self, mycrypto, myssl):
        myssl.crypto.dump_certificate.return_value = 'certificate'

        self.session = Session()
        self.push_con = self.session.get_connection("push_production", cert_string='certificate_content')
        self.same_push_con = self.session.get_connection("push_production", cert_string='certificate content')

        self.feed_con = Session.new_connection("feedback_production", cert_string='certificate_content')
        self.same_feed_con = Session.new_connection("feedback_production", cert_string='certificate_content')

    @patch('OpenSSL.SSL')
    def test_session(self, myssl):
        self.assertEqual(self.push_con, self.same_push_con)
        self.assertNotEqual(self.feed_con, self.same_feed_con)
        
        self.assertTrue(self.push_con.is_closed())
        self.push_con.refresh()
        self.assertFalse(self.push_con.is_closed())

        # can not outdate if few moments
        self.assertEqual(self.session.outdate(datetime.timedelta(minutes=5)), 0)
        self.assertFalse(self.push_con.is_closed())

        self.session.shutdown()
        self.assertTrue(self.push_con.is_closed())

    @patch('OpenSSL.SSL')
    def test_send(self, myssl):
        # fail on invalid token on second message
        myssl.Connection().recv.return_value = struct.pack(">BBI", 8, 8, 1)

        msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alert", badge=10, my_extra=15)
        self.push_con.close()
        srv = APNs(self.push_con)
        res = srv.send(msg)

        self.assertEqual(len(res.failed), 1)
        self.assertEqual(res.failed.keys()[0], "FEDCBA9876543210")
        # it was the last token and we skip it
        self.assertFalse(res.needs_retry())
        self.assertTrue(self.push_con.is_closed())

    @patch('OpenSSL.SSL')
    def test_feedback(self, myssl):
        myssl.ZeroReturnError = ZeroReturnError

        # fail on invalid token on second message
        token = "0123456789ABCDEF".decode("hex")
        curtime = int(time.time())
        myssl.Connection().recv.side_effect = [struct.pack(">IH%ss" % len(token), curtime, len(token), token), ZeroReturnError()]

        self.feed_con.close()
        srv = APNs(self.feed_con)
        feed = list(srv.feedback())
        self.assertEqual(len(feed), 1)
        self.assertEqual(feed[0], ('0123456789ABCDEF', datetime.datetime.fromtimestamp(curtime)))


class APNsClientMessageTest(unittest.TestCase):
    """ Test Message API. """

    def setUp(self):
        self.uni = Message("0123456789ABCDEF", alert="alert", badge=10)
        self.multi = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alerrt", sound="cool.mp3", my_extra=15)

    def test_serialization(self):
        # standard pickle
        suni = pickle.dumps(self.uni)
        smulti = pickle.dumps(self.multi)
        
        cuni = pickle.loads(suni)
        cmulti = pickle.loads(smulti)

        for key in ('tokens', 'alert', 'badge', 'sound', 'expiry', 'extra', '_payload'):
            self.assertEqual(getattr(self.uni, key), getattr(cuni, key))
            self.assertEqual(getattr(self.multi, key), getattr(cmulti, key))

        # custom
        suni = self.uni.__getstate__()
        smulti = self.multi.__getstate__()
        # JSON/XML/etc and store/send
        suni = json.dumps(suni)
        smulti = json.dumps(smulti)

        suni = dict((k.encode("UTF-8"), v) for k, v in json.loads(suni).iteritems())
        smulti = dict((k.encode("UTF-8"), v) for k, v in json.loads(smulti).iteritems())

        cuni = Message(**suni)
        cmulti = Message(**smulti)

        for key in ('tokens', 'alert', 'badge', 'sound', 'expiry', 'extra', '_payload'):
            self.assertEqual(getattr(self.uni, key), getattr(cuni, key))
            self.assertEqual(getattr(self.multi, key), getattr(cmulti, key))

    def test_batch(self):
        # binary serialization in ridiculously small buffer =)
        buni = list(self.uni.batch(10))
        bmulti = list(self.multi.batch(10))

        # number of batches
        self.assertEqual(len(buni), 1)
        self.assertEqual(len(bmulti), 2)

        # lets read stuff back. number of sent before ID's is of course 0.
        self.check_message(buni[0], 0, self.uni)
        self.check_message(bmulti[0], 0, self.multi)
        self.check_message(bmulti[1], 1, self.multi)

    def check_message(self, batch, itr, msg):
        sent, data = batch
        # we send batches of 1 token size
        self.assertEqual(sent, itr)
        # |COMMAND|ID|EXPIRY|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD|
        command, ID, expiry, tokenlen = struct.unpack(">BIIH", data[0:11])
        token = data[11:(11 + tokenlen)].encode("hex")
        payloadlen = struct.unpack(">H", data[(11 + tokenlen):(11 + tokenlen + 2)])[0]
        payload = json.loads(data[(11 + tokenlen + 2): (11 + tokenlen + 2 + payloadlen)])
        # test packaging
        self.assertEqual(command, 1)
        self.assertEqual(ID, itr)
        # test message
        self.assertEqual(msg.tokens[itr].lower(), token.lower())
        self.assertEqual(msg.expiry, expiry)
        self.assertEqual(msg.alert, payload['aps']['alert'])
        self.assertEqual(msg.badge, payload['aps'].get('badge'))
        self.assertEqual(msg.sound, payload['aps'].get('sound'))
        payload.pop('aps')
        self.assertEqual(msg.extra, payload)

    def test_retry(self):
        # include failed
        runi = self.uni.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'expiry', 'extra'):
            self.assertEqual(getattr(self.uni, key), getattr(runi, key))

        # nothing to retry, we skip the token
        self.assertEqual(self.uni.retry(0, False), None)

        # include failed
        rmulti = self.multi.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'expiry', 'extra'):
            self.assertEqual(getattr(self.multi, key), getattr(rmulti, key))

        # skip failed
        rmulti = self.multi.retry(0, False)
        self.assertEqual(self.multi.tokens[1:], rmulti.tokens)
        for key in ('alert', 'badge', 'sound', 'expiry', 'extra'):
            self.assertEqual(getattr(self.multi, key), getattr(rmulti, key))

    def test_non_ascii(self):
        # meta-data size
        empty_msg_size = len(Message(tokens=[], alert="").get_json_payload())

        MAX_UTF8_SIZE = 3  # size of maximum utf8 encoded character in bytes
        chinese_str = (
            u'\u5187\u869a\u5487\u6b8f\u5cca\u9f46\u9248\u6935\u4ef1\u752a'
            u'\u67cc\u521e\u62b0\u530a\u6748\u9692\u5c6e\u653d\u588f\u6678')
        chinese_msg_size = len(Message(tokens=[], alert=chinese_str).get_json_payload())
        self.assertLessEqual(
            chinese_msg_size,
            empty_msg_size + len(chinese_str) * MAX_UTF8_SIZE)

        MAX_EMOJI_SIZE = 4  # size of maximum utf8 encoded character in bytes
        # emoji
        emoji_str = (u'\U0001f601\U0001f603\U0001f638\U00002744')
        emoji_msg_size = len(Message(tokens="", alert=emoji_str).get_json_payload())
        self.assertLessEqual(
            emoji_msg_size,
            empty_msg_size + len(emoji_str) * MAX_EMOJI_SIZE)


class APNsClientResultTest(unittest.TestCase):
    """ Test Result API. """

    def setUp(self):
        self.msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alerrt", sound="cool.mp3", my_extra=15)

    def test_result(self):
        for reason in Result.ERROR_CODES.keys():
            res = Result(self.msg, (reason, 0))
            self.assertEqual(len(res.errors), int(reason in (1, 3, 4, 6, 7, None)))
            self.assertEqual(len(res.failed), int(reason in (2, 5, 8)))
            self.assertEqual(reason in (1, 2, 5, 8, None), res.needs_retry())

            if res.needs_retry():
                ret = res.retry()
                self.assertEqual(len(ret.tokens), 2 - len(res.failed))


if __name__ == '__main__':
    unittest.main()
