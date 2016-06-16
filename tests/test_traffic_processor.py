from network_poll_creator import TrafficProcessor
import os
import logging
logging.basicConfig()

pickled_files_dir = 'sample_pickled_files'
output_dir = 'test_out'
os.system('mkdir -p ' + output_dir)
for curr_file in os.listdir(pickled_files_dir):
    curr_f_path = os.path.join(pickled_files_dir, curr_file)
    curr_output_dir = os.path.join(output_dir, curr_file)
    os.system('mkdir -p ' + curr_output_dir)
    tp = TrafficProcessor(curr_f_path)
    all_polls = tp.get_polls()
    for i in range(len(all_polls)):
        if all_polls[i].to_cfe_xml() is not None:
            fp = open(os.path.join(curr_output_dir, str(all_polls[i].cs_id) + '_' + str(all_polls[i].connection_id) + '.xml'), 'w')
            fp.write(all_polls[i].to_cfe_xml())
            fp.close()
    print "Found:" + str(len(all_polls))
