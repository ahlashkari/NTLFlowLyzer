#### IAT ####

def IAT(packets):
    times = [packet.get_timestamp() for packet in packets]
    if len(times)>1:
        for i in range(len(times)-1):
            times[i] = times[i+1] - times[i]
        times.pop()
    return times

def flow_packets_IAT_mean(packets):
    times=IAT(packets)
    if times:
        return np.mean(times)
    else:
        return 0
    
def flow_packets_IAT_std(packets): # should be developed for NaN value
    times = IAT(packets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return 0
    except ValueError:
        return 0
    
def flow_packets_IAT_max(packets):
    times=IAT(packets)
    if times:
        return max(times)
    else:
        return 0
    
def flow_packets_IAT_min(packets):
    times=IAT(packets)
    if times:
        return min(times)
    else:
        return 0
    
def flow_packets_IAT_sum(packets):
    times = IAT(packets)
    if times:
        return sum(times)
    else:
        return 0

