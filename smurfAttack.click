define ($MAC 00:00:00:00:50:00)                                                                    
define ($IP 10.10.1.50)                                                                            
define ($BIP 10.10.1.255)    

source::FromDevice                                                                                
dest::ToDevice  

c::Classifier(12/0806 20/0001, 12/0800, -); 
filter::IPFilter(                                                                                           
              0 dst host $BIP,                                                                                    
              1 all); 
              
arpresponse::ARPResponder($IP $MAC)   
source -> c    
c[0] -> ARPPrint -> arpresponse -> dest;   
c[1] -> CheckIPHeader(14) -> filter;    
filter[0] -> Print('Malicious Packet. Hence Discarding') -> Discard;   
filter[1] -> ICMPPingResponder() -> Print('Legitimate Packet') -> EtherMirror() -> dest;    
c[2] -> Discard;



