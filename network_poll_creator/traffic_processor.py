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
    # flag, which indicates whether the msg ids are expected to be sequential
    # This will result in ignoring messages which are out of order.
    SEQUENTIAL_MSG_ID = False

    def __init__(self, cs_id, connection_id):
        self.cs_id = cs_id
        self.connection_id = connection_id
        self.data_elements = {}

    def to_cfe_xml(self, with_rand_seed=True):
        """
            Convert the current Poll Data in to CFE Poll and return the same
            :param with_rand_seed: Flag to indicate whether to append, random seed or not.
        :return: CFE Poll xml as string.
        """
        target_actions = []
        if PollData.SEQUENTIAL_MSG_ID:
            for msg_id in range(1, len(self.data_elements)):
                if msg_id in self.data_elements:
                    curr_data_element = self.data_elements[msg_id]
                    if curr_data_element.is_input:
                        match_attribute = Match([Data(curr_data_element.data)])
                        curr_action = Read(length=len(curr_data_element.data), match=match_attribute)
                    else:
                        curr_action = Write([Data(curr_data_element.data)])
                    target_actions.append(curr_action)
                else:
                    break
        else:
            ordered_dict = collections.OrderedDict(sorted(self.data_elements.items()))
            for msg_id, curr_data_element in ordered_dict.iteritems():
                if curr_data_element.is_input:
                        match_attribute = Match([Data(curr_data_element.data)])
                        curr_action = Read(length=len(curr_data_element.data), match=match_attribute)
                else:
                        curr_action = Write([Data(curr_data_element.data)])
                target_actions.append(curr_action)

        if len(target_actions) > 0:
            # header
            poll_header = """<?xml version="1.0" standalone="no" ?>
                            <!DOCTYPE pov SYSTEM "/usr/share/cgc-docs/replay.dtd">
                        """
            # create random seed, this may / will be changed in the process
            # to create a valid CFE POLL
            if with_rand_seed:
                rand_seed = binascii.b2a_hex(os.urandom(PollData.RANDOM_SEED_LENGTH))
                rand_seed = rand_seed[0:PollData.RANDOM_SEED_LENGTH]
            else:
                # instead of random seed, create a fixed length seed.
                rand_seed = "A" * PollData.RANDOM_SEED_LENGTH
            # create CFE POLL Object
            poll = CFE_POLL(str(self.cs_id), rand_seed, target_actions)
            # return the final Xml.
            return poll_header + str(poll)
        else:
            return None


class TrafficProcessor(object):
    """
        Processes the raw pickled data
    """
    INPUT_SIDE = 'client'

    def __init__(self, pickled_file):
        self.pickled_file = pickled_file

    def get_polls(self, remove_duplicates=True):
        """
        Processes the provided pickled file and returns list of PollData objects.
        :param remove_duplicates: Flag to remove duplicates from received polls.
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
                    msg_id = int(msg_id)
                    cache_l2_key = str(csid)
                    cache_l1_key = str(connection_id)
                    if cache_l2_key not in poll_cache:
                        # create a new Poll
                        poll_cache[cache_l2_key] = {}
                    if cache_l1_key not in poll_cache[cache_l2_key]:
                        poll_cache[cache_l2_key][cache_l1_key] = PollData(csid, connection_id)
                    curr_poll_data = poll_cache[cache_l2_key][cache_l1_key]
                    if side == TrafficProcessor.INPUT_SIDE:
                        network_data = InputData(message)
                    else:
                        network_data = OutputData(message)
                    # add data into correct poll
                    # assert msg_id not in curr_poll_data.data_elements
                    curr_poll_data.data_elements[msg_id] = network_data
                except EOFError as e:
                    break
            fp.close()
            # acts as cache of observed data
            observed_data = set()
            for l2_key in poll_cache:
                for l1_key in poll_cache[l2_key]:
                    curr_poll_data = poll_cache[l2_key][l1_key]
                    actual_cfe_xml = curr_poll_data.to_cfe_xml()
                    # first, check if the CFE xml contains any data.
                    if actual_cfe_xml is not None:
                        if remove_duplicates:
                            # we need to get non-random data to remove duplicates.
                            non_random_data = curr_poll_data.to_cfe_xml(with_rand_seed=False)
                            # already observed?
                            if non_random_data not in observed_data:
                                # if no, insert into returning items.
                                observed_data.add(non_random_data)
                                to_ret.append(curr_poll_data)
                            else:
                                l.warning("Ignoring Connection:" + str(l1_key) + " for CS:" + str(l2_key) +
                                          " as it is a duplicate")
                        else:
                            to_ret.append(curr_poll_data)
                    l.warning("Ignoring Connection:" + str(l1_key) + " for CS:" + str(l2_key) +
                              " as there is no captured data")

            l.info("Got:" + str(len(to_ret)) + " Polls.")
        else:
            l.error("Provided pickled file:" + str(self.pickled_file) + " does not exist.")
        return to_ret
