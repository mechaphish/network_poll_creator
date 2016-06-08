import os
import pickle
from farnsworth.actions import CQE_POV, Data, Write, Read, Match
import logging
import collections

l = logging.getLogger("network_poll_creator.traffic_processor")


class NetworkData(object):

    def __init__(self, target_data):
        """

        :param target_data:
        :return:
        """
        self.target_data = target_data
        self._is_input = False
        self._is_output = False

    @property
    def is_input(self):
        """

        :return:
        """
        return self._is_input

    @property
    def is_output(self):
        """

        :return:
        """
        return self._is_output

    @property
    def data(self):
        """

        :return:
        """
        return self.target_data


class InputData(NetworkData):
    """

    """

    def __init__(self, target_data):
        NetworkData.__init__(self, target_data)
        self._is_input = True


class OutputData(NetworkData):
    """

    """

    def __init__(self, target_data):
        NetworkData.__init__(self, target_data)
        self._is_output = True


class PollData(object):
    """

    """

    def __init__(self, cs_id, connection_id):
        self.cs_id = cs_id
        self.connection_id = connection_id
        self.data_elements = {}

    def to_cqe_xml(self):
        """

        :return:
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
        # create CQE POV Object
        poll = CQE_POV(str(self.cs_id), target_actions)
        # return the final Xml.
        return poll_header + str(poll)


class TrafficProcessor(object):
    """

    """
    INPUT_SIDE = 'client'

    def __init__(self, pickled_file):
        self.pickled_file = pickled_file

    def get_polls(self):
        """

        :return:
        """
        # No polls
        to_ret = []
        poll_cache = {}
        if os.path.exists(self.pickled_file):
            fp = open(self.pickled_file, 'rb')
            while True:
                try:
                    csid, connection_id, msg_id, side, message = pickle.load(fp)
                    cache_key = str(csid) + ',' + str(connection_id)
                    if cache_key not in poll_cache:
                        poll_cache[cache_key] = PollData(csid, connection_id)
                    curr_poll_data = poll_cache[cache_key]
                    if side == TrafficProcessor.INPUT_SIDE:
                        network_data = InputData(message)
                    else:
                        network_data = OutputData(message)
                    curr_poll_data.data_elements[msg_id] = network_data
                except EOFError as e:
                    break
            fp.close()
            to_ret = list(poll_cache.values())
        return to_ret

target_fp = '/home/machiry/Downloads/raw_pickled_traffic'
new_tp = TrafficProcessor(target_fp)
all_polls = new_tp.get_polls()
for curr_p in all_polls:
    curr_x = curr_p.to_cqe_xml()
    fp = open(str(curr_p.cs_id) + '_' + str(curr_p.connection_id) + '.xml', 'w')
    fp.write(curr_x)
    fp.close()