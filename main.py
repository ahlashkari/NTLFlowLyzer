from netflowmeter import Netflowmeter

def main():
    nfm = Netflowmeter()
    nfm.run('data.pcap')

if __name__=="__main__":
    main()
    
