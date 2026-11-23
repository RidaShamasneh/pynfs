"""A big reply must not cost a megabyte of log formatting (needs no server).

pynfs used to format the whole record with %r for its debug logging before
checking whether that was wanted, which is megabytes of text and several
times the cost of the read itself, for TCP as well as RDMA.
"""
import types
import unittest
from unittest import mock

from .common import rdma          # also sets up the import paths
import rpc.rpc as rpc
from rpc.rpc_const import (REPLY, MSG_ACCEPTED, SUCCESS)
from rpc.rpc_type import (rpc_msg, rpc_msg_body, reply_body, accepted_reply,
                          rpc_reply_data)
from rpc import rpclib

BIG = 2000000


class RecordingLogger(object):
    """Keeps the arguments of every call, formats nothing."""
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def log(*args, **kwargs):
            self.calls.append((name, args))
        return log


def reply_record(data):
    packer = rpc.FancyRPCPacker()
    packer.pack_rpc_msg(rpc_msg(7, rpc_msg_body(REPLY, rbody=reply_body(
        MSG_ACCEPTED, areply=accepted_reply(
            rpclib.NULL_CRED, rpc_reply_data(SUCCESS, b""))))))
    return packer.get_buffer() + data


class BigReply(unittest.TestCase):
    def test_a_big_reply_is_not_formatted_for_the_log(self):
        record = reply_record(b"\xff\x00\x7f" * (BIG // 3))
        seen = []
        handler = types.SimpleNamespace(
            _event_rpc_reply=lambda msg, data, pipe: seen.append(len(data)),
            _notify_drop=lambda: None)
        logger = RecordingLogger()
        with mock.patch.object(rpc, "log_t", logger):
            rpc.ConnectionHandler._event_rpc_record(handler, record, None)
        self.assertEqual(seen, [BIG // 3 * 3])          # the reply got through
        self.assertTrue(logger.calls)                   # and it did log
        for name, args in logger.calls:
            # log(level, format, ...) or debug(format, ...): the format
            # string must be the short one, the data only an argument
            fmt = args[1] if name == "log" else args[0]
            self.assertLess(len(fmt), 1000, (name, fmt[:80]))

    def test_the_poll_loop_does_not_format_its_sets_either(self):
        """It logs the sockets it waits on at every pass."""
        import inspect
        source = inspect.getsource(rpc.ConnectionHandler.start)
        self.assertNotIn('" %\n', source)
        self.assertNotIn('log_p.log(5, "Woke with: %s, %s, %s" %', source)


if __name__ == "__main__":
    unittest.main()
