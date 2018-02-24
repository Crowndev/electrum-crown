# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading

from . import util
from .bitcoin import *

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
VERISON_AUXPOW = (1 << 8)


def _serialize_plain_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s


def serialize_header(res, auxpow=False):
    s = _serialize_plain_header(res)
    if auxpow:
        # even for non auxpow block serialized header size should be AUX_HEADER_SIZE
        if not res.get('parent_block') or res.get('parent_block') == '0'*NetworkConstants.AUX_HEADER_SIZE:
            s += '0'*NetworkConstants.AUX_HEADER_SIZE
        else:
            s += _serialize_plain_header(res.get('parent_block'))
    return s


def _deserialize_plain_header(s):
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    return h


def deserialize_header(s, height):
    assert len(s) == NetworkConstants.AUX_HEADER_SIZE
    h = _deserialize_plain_header(s[:NetworkConstants.PLAIN_HEADER_SIZE])
    h['block_height'] = height
    # FIXME we don't recover dummy objects for now
    if h['version'] & VERISON_AUXPOW:
        h['parent_block'] = _deserialize_plain_header(s[-NetworkConstants.PLAIN_HEADER_SIZE:])
    return h


def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = NetworkConstants.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//NetworkConstants.AUX_HEADER_SIZE if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash):
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("at height %s prev hash mismatch: %s vs %s" % (header.get('block_height'),
                                                                               prev_hash, header.get('prev_block_hash')))
        if NetworkConstants.TESTNET:
            return

        # for the range (last_checkpoint, last_checkpoint + 24] the headers proof of work validation skipped
        # as for dgw calculation last 24 blocks should be exist in db
        skipped_range = header['block_height'] - len(self.checkpoints) * NetworkConstants.RETARGET_SIZE
        if skipped_range != 0 and skipped_range < 25 and header['block_height'] >= NetworkConstants.DGW_FIRST_BLOCK:
            self.print_error('proof of work validation skipped for the header at height: %d' % header['block_height'])
            return

        target = self.calculate_target(header['block_height'])
        bits = self.target_to_bits(target)
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        # for auxpow blocks proof of work verification done based on parent_block hash value
        if not header.get('parent_block') or header.get('parent_block') == '0'*NetworkConstants.AUX_HEADER_SIZE:
            # Non auxpow version block
            _hash = hash_header(header)
        else:
            _hash = hash_header(header.get('parent_block'))
        if int('0x' + _hash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def verify_chunk(self, index, data):
        num = len(data) // NetworkConstants.AUX_HEADER_SIZE
        prev_hash = self.get_hash(index * NetworkConstants.CHUNK_SIZE - 1)
        for i in range(num):
            raw_header = data[i*NetworkConstants.AUX_HEADER_SIZE:(i+1) * NetworkConstants.AUX_HEADER_SIZE]
            header = deserialize_header(raw_header, index*NetworkConstants.CHUNK_SIZE + i)
            self.verify_header(header, prev_hash)
            self.save_header(header)
            prev_hash = hash_header(header)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * NetworkConstants.CHUNK_SIZE - self.checkpoint) * NetworkConstants.AUX_HEADER_SIZE
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        self.write(chunk, d, index > len(self.checkpoints))
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*NetworkConstants.AUX_HEADER_SIZE)
            parent_data = f.read(parent_branch_size*NetworkConstants.AUX_HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*NetworkConstants.AUX_HEADER_SIZE)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*NetworkConstants.AUX_HEADER_SIZE:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header, auxpow=True))
        # FIXME remove after tests!! assert isn't needed as the chunk is saved header by header
        # assert delta == self.size()
        assert len(data) == NetworkConstants.AUX_HEADER_SIZE
        self.write(data, delta*NetworkConstants.AUX_HEADER_SIZE)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * NetworkConstants.AUX_HEADER_SIZE)
                h = f.read(NetworkConstants.AUX_HEADER_SIZE)
        if h == bytes([0])*NetworkConstants.AUX_HEADER_SIZE:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return NetworkConstants.GENESIS
        elif height < len(self.checkpoints) * NetworkConstants.RETARGET_SIZE:
            assert (height+1) % NetworkConstants.RETARGET_SIZE == 0, height
            index = height // NetworkConstants.RETARGET_SIZE
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))

    def calculate_target(self, height):
        """
        Method calculates target based on header height as
        crown used different difficulty formulas during evolution.
        """
        if NetworkConstants.TESTNET:
            return 0

        # new target
        if height >= NetworkConstants.DGW_FIRST_BLOCK:
            return self.calculate_dgw_target(height)
        else:
            return self.calculate_btc_style_target(height)

    def calculate_dgw_target(self, height):
        """
        Method calculates new target using new difficulty formula: Dark Gravity Wave v3:
        see https://github.com/Crowndev/crowncoin/blob/master/src/pow.cpp
        """
        # use checkpoints value only for first header in case of dgw
        if not height % NetworkConstants.RETARGET_SIZE:
            index = height // NetworkConstants.RETARGET_SIZE - 1
            if index < len(self.checkpoints):
                h, t = self.checkpoints[index]
                return t
        # get last solved header
        current = self.read_header(height - 1)
        actual_timespan = 0
        last_block_time = 0
        past_blocks_min = past_blocks_max = 24
        blocks_count = 0

        for i in range(past_blocks_max):
            blocks_count += 1
            if not current:
                raise BaseException('header at height: %d is not stored in db' % (height - i - 1))
            bits = current.get('bits')
            if blocks_count <= past_blocks_min:
                if blocks_count == 1:
                    past_difficulty_avg = self.bits_to_target(bits)
                else:
                    past_difficulty_avg = (past_difficulty_avg_prev * blocks_count + self.bits_to_target(bits)) // (blocks_count + 1)
                past_difficulty_avg_prev = past_difficulty_avg

            if last_block_time > 0:
                actual_timespan += last_block_time - current.get('timestamp')
            last_block_time = current.get('timestamp')

            # get previous block
            current = self.read_header(height - i - 2)

        target_timespan = blocks_count * NetworkConstants.TARGET_SPACING
        actual_timespan = max(actual_timespan, target_timespan // 3)
        actual_timespan = min(actual_timespan, target_timespan * 3)
        new_target = min(MAX_TARGET, (past_difficulty_avg * actual_timespan) // target_timespan)

        return new_target

    def calculate_btc_style_target(self, height):
        """
        Method calculates new target using default Bitcoin style re-targeting
        """
        index = height // NetworkConstants.RETARGET_SIZE - 1
        if index == -1:
            return MAX_TARGET

        if index < len(self.checkpoints):
            h, t = self.checkpoints[index]
            return t

        first = self.read_header(index * NetworkConstants.RETARGET_SIZE)
        last = self.read_header(index * NetworkConstants.RETARGET_SIZE + NetworkConstants.RETARGET_SIZE - 1)
        bits = last.get('bits')
        target = self.bits_to_target(bits)
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
        return new_target

    def bits_to_target(self, bits):
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1d):
            raise BaseException("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    def target_to_bits(self, target):
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header) == NetworkConstants.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            self.verify_header(header, prev_hash)
        except BaseException as e:
            self.print_error('verify_header failed', str(e))
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            self.print_error("validated chunk %d" % idx)
            return True
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // NetworkConstants.RETARGET_SIZE
        for index in range(n):
            hash = self.get_hash((index + 1) * NetworkConstants.RETARGET_SIZE - 1)
            target = self.calculate_target((index + 1) * NetworkConstants.RETARGET_SIZE)
            cp.append((hash, target))
        return cp
