import math
import numpy as np
from deepbindiff import Article

import tensorflow as tf
import config

class Word2Vec(tf.keras.Model):
    def __init__(self, vocab_size, embedding_dim):
        super(Word2Vec, self).__init__()
        self.token_embedding = tf.keras.layers.Embedding(vocab_size+1,embedding_dim)
        self.nce_weight = tf.Variable(tf.random.truncated_normal([vocab_size,2*embedding_dim],stddev=1.0/math.sqrt(2*embedding_dim)))
        self.nce_bias = tf.Variable(tf.zeros([vocab_size]))

    # input: (batch_size,2,5)
    def call(self, input):
        embeddings = self.token_embedding(input)
        embeddings = tf.reduce_sum(embeddings,1)
        embeddings = tf.squeeze(embeddings) # (batch_size,5,embedding_size)
        opcodes,oprands=tf.split(embeddings,[1,6],1)
        opcodes = tf.squeeze(opcodes)
        oprands = tf.reduce_sum(oprands,1)
        insns = tf.concat([opcodes,oprands],1)
        # divide ?
        return insns

def generate_token_embeddings(article: Article, vocab_size):
    optmizer = tf.keras.optimizers.SGD(learning_rate=0.01)
    model = Word2Vec(vocab_size,config.embedding_size)

    for step in range(6001):
        data,labels=article.batch(config.batch_size)
        data = np.array(data)
        labels = np.array(labels).reshape((128,1))
        with tf.GradientTape() as tape:
            insns = model(data,training=True)
            loss = tf.nn.nce_loss(model.nce_weight,model.nce_bias,labels,inputs=insns,num_sampled=64,num_classes=vocab_size)
            loss = tf.reduce_mean(loss)
        grads = tape.gradient(loss,model.variables) # trained_weight ?
        optmizer.apply_gradients(zip(grads,model.variables))
        if step % 2000 == 0:
            print('step',step,'loss',loss)
    return model.token_embedding.weights[0].numpy()

def generate_token_embeddings2(dataSet,vocab_size):
    optmizer = tf.keras.optimizers.SGD(learning_rate=0.01)
    model = Word2Vec(vocab_size,config.embedding_size)

    batch_dataset = dataSet.batch(config.batch_size, drop_remainder=True)

    for step in range(6001):
        data,labels = batch_dataset.take(1).get_single_element()
        labels=tf.reshape(labels,(-1,1))
        with tf.GradientTape() as tape:
            insns = model(data,training=True)
            loss = tf.nn.nce_loss(model.nce_weight,model.nce_bias,labels,inputs=insns,num_sampled=64,num_classes=vocab_size)
            loss = tf.reduce_mean(loss)
        grads = tape.gradient(loss,model.variables) # trained_weight ?
        optmizer.apply_gradients(zip(grads,model.variables))
        if step % 2000 == 0:
            print('step',step,'loss',loss)
    return model.token_embedding.weights[0].numpy()