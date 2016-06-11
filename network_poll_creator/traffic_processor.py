import os
import pickle
from farnsworth.actions import CFE_POLL, Data, Write, Read, Match
from common_utils.pcap_parser import InputData, OutputData
import logging
import binascii
import collections

l = logging.getLogger("network_poll_creator.traffic_processor")


class PollData(object):
    """
        Object representing interaction of one challenge set.
    """

    RANDOM_SEED_LENGTH = 96

    def __init__(self, cs_id, connection_id):
        self.cs_id = cs_id
        self.connection_id = connection_id
        self.data_elements = {}

    def to_cfe_xml(self):
        """
            Convert the current Poll Data in to CFE Poll and return the same
        :return: CFE Poll xml as string.
        """
        target_actions = []
        ordered_dict = collections.OrderedDict(sorted(self.data_elements.items()))
        for msg_id, curr_data_element in ordered_dict.iteritems():
            if curr_data_element.is_input:
                match_attribute = Match([Data(curr_data_element.data)])
                curr_action = Read(length=len(curr_data_element.data), match=match_attribute)
            else:
                curr_action = Write([Data(curr_data_element.data)])
            target_actions.append(curr_action)

        # header
        poll_header = """<?xml version="1.0" standalone="no" ?>
                        <!DOCTYPE pov SYSTEM "/usr/share/cgc-docs/replay.dtd">
                    """
        # create random seed, this may / will be changed in the process
        # to create a valid CFE POLL
        rand_seed = binascii.b2a_hex(os.urandom(PollData.RANDOM_SEED_LENGTH))
        rand_seed = rand_seed[0:PollData.RANDOM_SEED_LENGTH]
        # create CFE POLL Object
        poll = CFE_POLL(str(self.cs_id), rand_seed, target_actions)
        # return the final Xml.
        return poll_header + str(poll)


class TrafficProcessor(object):
    """
        Processes the raw pickled data
    """
    INPUT_SIDE = 'client'

    def __init__(self, pickled_file):
        self.pickled_file = pickled_file

    def get_polls(self):
        """
        Processes the provided pickled file and returns list of PollData objects.

        :return: list of poll data objects
        """
        # No polls
        to_ret = []
        poll_cache = {}
        if os.path.exists(self.pickled_file):
            l.info("Trying to read pickled file:" + str(self.pickled_file))
            fp = open(self.pickled_file, 'rb')
            # Try to load pickled data until End of File
            while True:
                try:
                    # load pickled data
                    csid, connection_id, msg_id, side, message = pickle.load(fp)
                    cache_key = str(csid) + ',' + str(connection_id)
                    if cache_key not in poll_cache:
                        # create a new Poll
                        poll_cache[cache_key] = PollData(csid, connection_id)
                    curr_poll_data = poll_cache[cache_key]
                    if side == TrafficProcessor.INPUT_SIDE:
                        network_data = InputData(message)
                    else:
                        network_data = OutputData(message)
                    # add data into correct poll
                    curr_poll_data.data_elements[msg_id] = network_data
                except EOFError as e:
                    break
            fp.close()
            to_ret = list(poll_cache.values())
            l.info("Got:" + str(len(to_ret)) + " Polls.")
        else:
            l.error("Provided pickled file:" + str(self.pickled_file) + " does not exist.")
        return to_ret
