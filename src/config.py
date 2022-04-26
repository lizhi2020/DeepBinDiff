import logging
# CONFIGURATION

batch_size = 128
embedding_size = 64  # Dimension of the embedding vector.
skip_window = 2       # How many words to consider left and right.
num_skips = 2         # How many times to reuse an input to generate a label.

# We pick a random validation set to sample nearest neighbors. Here we limit the
# validation samples to the words that have a low numeric ID, which by
# construction are also the most frequent.
valid_size = 16     # Random set of words to evaluate similarity on.
valid_window = 100  # Only pick dev samples in the head of the distribution.
# valid_examples = np.random.choice(valid_window, valid_size, replace=False)
num_sampled = 64    # Number of negative examples to sample.

#num_steps = 100001
prev_data_index = 0
data_index = 0

random_walk_done = False

logger_name = 'dbdlogger'
log_level = logging.INFO
dbdlogger = logging.getLogger(logger_name)
formatter = logging.Formatter("[%(asctime)s|%(levelname)s|%(name)-8s]:%(message)s")

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(log_level)
ch.setFormatter(formatter)

# add ch to logger
dbdlogger.addHandler(ch)
dbdlogger.propagate = False
dbdlogger.setLevel(log_level)

embedding_filename = "vec_all.txt"
node_filename = "node.txt"
edgelist_filename = "edgelist.txt"
features_filename = "features.txt"