#!/usr/bin/env python3
 
from collections import Counter
from ..network_flow_capturer import Flow
import numpy as np
import scipy as sp
import math

def calculate_flow_payload_bytes(flow: Flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_packets()]
    return sum(total_bytes)


def calculate_fwd_flow_payload_bytes(flow: Flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_forwardpackets()]
    return sum(total_bytes)


def calculate_bwd_flow_payload_bytes(flow: Flow):
    total_bytes = [packet.get_payloadbytes() for packet in flow.get_backwardpackets()]
    return sum(total_bytes)


def calculate_IAT(packets: list):
    times = [packet.get_timestamp() for packet in packets]
    if len(times) > 1:
        for i in range(len(times) - 1):
            times[i] = times[i + 1] - times[i]
        times.pop()
    times = [float(t) for t in times]
    return times


def calculate_flow_duration(flow: Flow):
    return float(flow.get_flow_last_seen() - flow.get_flow_start_time())

def calculate_flow_header_bytes(packets: list):
    header_size = 0
    for packet in packets:
        header_size += packet.get_header_size()
    return header_size

def ctransform(x):
    xi = np.argsort(np.atleast_2d(x))
    xr = np.argsort(xi)
    cx = (xr+1).astype(np.float64) / (xr.shape[-1]+1)
    return cx

def copnorm(x):
    #cx = sp.stats.norm.ppf(ctransform(x))
    cx = sp.special.ndtri(ctransform(x))
    return cx

def mi_gg(x, y, biascorrect=True, demeaned=False):
    """
    Mutual information gaussian copula estimator: https://github.com/robince/gcmi
    """
    x = np.atleast_2d(x)
    y = np.atleast_2d(y)
    if x.ndim > 2 or y.ndim > 2:
        raise ValueError("x and y must be at most 2d")
    Ntrl = x.shape[1]
    Nvarx = x.shape[0]
    Nvary = y.shape[0]
    Nvarxy = Nvarx+Nvary

    if y.shape[1] != Ntrl:
        raise ValueError("number of trials do not match")

    # joint variable
    xy = np.vstack((x,y))
    if not demeaned:
        xy = xy - xy.mean(axis=1)[:,np.newaxis]
    Cxy = np.dot(xy,xy.T) / float(Ntrl - 1)
    # submatrices of joint covariance
    Cx = Cxy[:Nvarx,:Nvarx]
    Cy = Cxy[Nvarx:,Nvarx:]

    chCxy = np.linalg.cholesky(Cxy)
    chCx = np.linalg.cholesky(Cx)
    chCy = np.linalg.cholesky(Cy)

    # entropies in nats
    # normalizations cancel for mutual information
    HX = np.sum(np.log(np.diagonal(chCx))) # + 0.5*Nvarx*(np.log(2*np.pi)+1.0)
    HY = np.sum(np.log(np.diagonal(chCy))) # + 0.5*Nvary*(np.log(2*np.pi)+1.0)
    HXY = np.sum(np.log(np.diagonal(chCxy))) # + 0.5*Nvarxy*(np.log(2*np.pi)+1.0)

    ln2 = np.log(2)
    if biascorrect:
        psiterms = sp.special.psi((Ntrl - np.arange(1,Nvarxy+1)).astype(np.float64)/2.0) / 2.0
        dterm = (ln2 - np.log(Ntrl-1.0)) / 2.0
        HX = HX - Nvarx*dterm - psiterms[:Nvarx].sum()
        HY = HY - Nvary*dterm - psiterms[:Nvary].sum()
        HXY = HXY - Nvarxy*dterm - psiterms[:Nvarxy].sum()

    # MI in bits
    I = (HX + HY - HXY) / ln2
    return I

def renyi_entropy(data, alpha):
  if alpha < 0 or alpha == 1:
      raise ValueError("Alpha must be positive and not equal to 1 for Rényi entropy.")
  data_int = np.frombuffer(data, dtype=np.uint8)
  chunk_size = 100000  
  entropy_sum = 0.0

  for chunk_start in range(0, len(data_int), chunk_size):
      chunk = data_int[chunk_start:chunk_start + chunk_size]
      p_chunk = np.frompyfunc(lambda x: x / len(chunk), 1, 1)(chunk)
      p_chunk = np.clip(p_chunk, np.finfo(float).eps, 1.0).astype(np.float64)
      log_p_chunk_alpha = np.log(p_chunk) * alpha
      entropy_sum += np.logaddexp.reduce(log_p_chunk_alpha)

  entropy = (-1 / (1 - alpha)) * np.log(entropy_sum)
  return entropy

def binary_derivative(bits, k=1):
  if k == 0:
    return bits  
  else:
    return binary_derivative(bits[1:] ^ bits[:-1], k-1)

def tbien(bits):
  """
  BiEntropy randomness metric: https://github.com/sandialabs/bientropy
  """
  l = 0
  t = 0
  if bits.len == 1:
    raise ValueError(
        'The input string is too short for the TBiEn algorithm.')
  s_k = bits
  for k in range(bits.len - 1):
    ones = s_k.count(1)
    n = s_k.len
    p = float(ones) / n
    e = 0 if p == 0 else -p * math.log(p, 2)
    g = 0 if p == 1 else -1 * (1 - p) * math.log(1 - p, 2)
    l_k = math.log(k + 2, 2)
    t_k = (e + g) * l_k
    l += l_k
    t += t_k
    s_k = binary_derivative(s_k) 
  return (1. / l) * t

def get_xy_from_data(data, sequence_length=64):
  if len(data) < sequence_length:
    raise ValueError("Data length must be greater than or equal to the desired sequence length.")

  X = data[:sequence_length] 
  Y = data[sequence_length:sequence_length * 2]  

  padding_size = abs(len(X) - len(Y))
  if padding_size > 0:
    if len(X) < len(Y):
      X = X + bytearray([0] * padding_size)
    else:
      Y = Y + bytearray([0] * padding_size)

  return X, Y

def analyze_mutual_information(data, seq_len=64):
  if not isinstance(data, bytes):
      raise ValueError("Input data must be bytes.")
  
  if seq_len > len(data):
    padding_size = seq_len - len(data)
    data += bytearray([0] * padding_size)


  mi_values = []
  for i in range(len(data) - seq_len + 1):
     X, Y = get_xy_from_data(data, seq_len)
     X_int = np.frombuffer(X, dtype=np.uint8)
     Y_int = np.frombuffer(Y, dtype=np.uint8)
     X_norm = copnorm(X_int)  
     Y_norm = copnorm(Y_int)  
     try:
        mi = mi_gg(X_norm, Y_norm)
     except :
        mi = 0  
     mi_values.append(mi)
  return mi_values

def analyze_binary_entropy(data, sequence_length):
  entropy_values = []
  for i in range(len(data) - sequence_length + 1): 
    chunk = data[i:i + sequence_length] 
    p = Counter(chunk) 
    entropy = 0
    for count in p.values():
      if count > 0:
        p_x = count / sequence_length
        entropy -= p_x * math.log2(p_x)
    entropy_values.append(entropy)
  return  entropy_values      


def analyze_ngram_entropy(data, sequence_length):
   ngrams = [data[i:i+sequence_length] for i in range(len(data) - sequence_length + 1)]
   ngram_counts = Counter(ngrams)
   total_ngrams = len(ngrams)

   entropy = 0
   for ngram, count in ngram_counts.items():
    p_ngram = count / total_ngrams
    entropy -= p_ngram * math.log2(p_ngram)

    return entropy
