import socket
from struct import pack,unpack
from json import loads, dumps
from base64 import b64encode, b64decode
from binascii import hexlify,unhexlify
from cmac import CMAC
import time

"""GWMP Identifiers"""
PUSH_DATA = 0
PUSH_ACK = 1
PULL_DATA = 2
PULL_RESP = 3
PULL_ACK = 4
TX_ACK = 5

class Rxpk(object):
    """A Gateway Rxpk (upstream) JSON object.
    
    The root JSON object shall contain zero or more rxpk
    objects. See Gateway to Server Interface Definition
    Section 6.2.2.
    
    Attributes:
        tmst (int): value of the gateway time counter when the
                    frame was received (us precision).
        freq (float): Centre frequency of recieved signal (MHz).
        chan (int): Concentrator IF channel on which the frame
                    was received.
        rfch (int): Concentrator RF chain on which the frame
                    was received.
        stat (int): The result of the gateway's CRC test on the
                    frame - 1 = correct, -1 = incorrect, 0 = no test.
        modu (str): Modulation technique - "LORA" or "FSK".
        datr (str): Datarate identifier. For Lora, comprised of
                    "SFnBWm where n is the spreading factor and
                    m is the frame's bandwidth in kHz.
        codr (str): ECC code rate as "k/n" where k is carried
                    bits and n is total bits received.
        rssi (int): The measured received signal strength (dBm).
        lsnr (float): Measured signal to noise ratio (dB).
        data (str): Frame payload encoded in Base64.
        time (str): UTC time of the LoRa frame (us precision).
        size (int): Number of octects in the received frame.
    
    """
    
    def __init__(self, tmst=None, freq=None, chan=None, rfch=None,
                 stat=None, modu=None, datr=None, codr=None, rssi=None,
                 lsnr=None, data=None, time=None, size=None):
        """Rxpk initialisation method.
        
        """
        self.tmst = tmst
        self.freq = freq
        self.chan = chan
        self.rfch = rfch
        self.stat = stat
        self.modu = modu
        self.datr = datr
        self.codr = codr
        self.rssi = rssi
        self.lsnr = lsnr
        self.data = data
        self.time = time        
        self.size = size
                
    @classmethod
    def decode(cls, rxp):
        """Decode Rxpk JSON dictionary.
            
        Args:
            rxp (dict): Dict representation of rxpk JSON object.
        
        Returns:
            Rxpk object if successful, None otherwise.
            
        """
        
        rkeys = rxp.keys()
        # Check mandatory fields exist
        mandatory = ('tmst', 'freq', 'chan', 'rfch',
                     'stat', 'modu', 'datr', 'codr',
                     'rssi', 'lsnr', 'data')
        if not all (rkeys for k in mandatory):
            return None
        # Mandatory attributes
        tmst = int(rxp['tmst'])
        freq = float(rxp['freq'])        
        chan = int(rxp['chan'])
        rfch = int(rxp['rfch'])
        stat = int(rxp['stat'])
        modu = rxp['modu']
        datr = rxp['datr']
        codr = rxp['codr']
        rssi = int(rxp['rssi'])
        lsnr = float(rxp['lsnr'])
        data = b64decode(rxp['data'])
        # Optional attributes
        time = rxp['time'] if 'time' in rkeys else None
        size = int(rxp['size']) if 'size' in rkeys else None        
        a = Rxpk(tmst=tmst, freq=freq, chan=chan, rfch=rfch, stat=stat,
                    modu=modu, datr=datr, codr=codr, rssi=rssi, lsnr=lsnr,
                    data=data, time=time, size=size)


        for m, v in a.__dict__.items():
            try:
                for attr, value in v.__dict__.items():
                    print('    '+attr, value)
            except:
                print(m, v)
                continue
        
        return a

class Stat(object):
    """A Gateway Stat (upstream) JSON object.
    
    The root JSON object shall contain zero or one stat
    objects. See Gateway to Server Interface Definition
    Section 6.2.1.
    
    Attributes:
        time (str): UTC time of the LoRa frame (us precision).
        lati (float): Gateway latitude in degress north of the equator.
        long (float): Gateway longitude in degress north of the equator.
        alti (int): Altitude of the gateway's position in metres above sea
                    level
        rxnb (int): Number of radio frames received since gateway start.
        rxok (int): Number of radio frames received with correct CRC since
                    gateway start.
        rwfw (int): Number of radio frames forwarded to the network server
                    since gateway start.
        ackr (int): Percentage of radio frames forwarded to the network
                    server, and acknowledged by the server since gateway
                    start.
        dwnb (int): Number of radio frames received from the network server
                    since gateway start.
        txnb (int): Number of radio frames transmitted since gateway start.
    
    """
    
    def __init__(self):
        """Stat initialisation method.
        
        """
        self.time = None
        self.lati = None
        self.long = None
        self.alti = None
        self.rxnb = None
        self.rxok = None
        self.rwfw = None
        self.ackr = None
        self.dwnb = None
        self.txnb = None
    
    @classmethod
    def decode(cls, stp):
        """Decode Stat JSON dictionary.
        
        Args:
            stp (dict): Dict representation of stat JSON object.
        
        Returns:
            Stat object.
            
        """
        
        skeys = stp['stat'].keys()
        s = Stat()
        
        # Set the attributes
        s.time = stp['stat']['time'] if 'time' in skeys else None
        s.lati = float(stp['stat']['lati']) if 'lati' in skeys else None
        s.long = float(stp['stat']['long']) if 'long' in skeys else None
        s.alti = int(stp['stat']['alti']) if 'alti' in skeys else None
        s.rxnb = int(stp['stat']['rxnb']) if 'rxnb' in skeys else None
        s.rxok = int(stp['stat']['rxok']) if 'rxok' in skeys else None
        s.rwfw = int(stp['stat']['rwfw']) if 'rwfw' in skeys else None
        s.ackr = int(stp['stat']['ackr']) if 'ackr' in skeys else None
        s.dwnb = int(stp['stat']['dwnb']) if 'dwnb' in skeys else None
        s.txnb = int(stp['stat']['txnb']) if 'txnb' in skeys else None

        print('STAT PACKET')
        for attr, value in s.__dict__.items():
            print(attr, value)
        return s

class GatewayMessage():
    """A Gateway Message.
    
    Messages sent between the LoRa gateway and the LoRa network
    server. The gateway message protocol operates over UDP and
    occupies the data area of a UDP packet. See Gateway to Server
    Interface Definition.
    
    Attributes:
        version (int): Protocol version - 0x01 or 0x02
        token (str): Arbitrary tracking value set by the gateway.
        id (int): Identifier - see GWMP Identifiers above.
        gatewayEUI (str): Gateway device identifier.
        payload (str): GWMP payload.
        remote (tuple): Gateway IP address and port.
        ptype (str): JSON protocol top-level object type.
    """

    def __init__(self, version=2, token=0, identifier=None,
                 gatewayEUI=None, txpk=None, remote=None,
                 ptype=None):
        """GatewayMessage initialisation method.
        
        Args:
            version (int): GWMP version.
            token (str): Message token.
            id: GWMP identifier.
            gatewayEUI: gateway device identifier.
            payload: GWMP payload.
            ptype (str): payload type
            remote: (host, port)
            
        Raises:
            TypeError: If payload argument is set to None.
        
        """
        self.version = version
        self.token = token
        self.id = identifier
        self.gatewayEUI = gatewayEUI
        self.payload = ''
        self.ptype = ptype
        self.remote = remote
        
        self.rxpk = None
        self.txpk = txpk
        self.stat = None
    
    @classmethod
    def decode(cls, data, remote):
        """Create a Message object from binary representation.
        
        Args:
            data (str): UDP packet data.
            remote (tuple): Gateway address and port.
        
        Returns:
            GatewayMessage object on success.
            
        """
        # Check length
        if len(data) < 4:
            raise DecodeError("Message too short.")
        # Decode header
        (version, token, identifer) = unpack('<BHB', data[:4])
        #print('Received Token', token)
        m = GatewayMessage(version=version, token=token, identifier=identifer)
        m.remote = remote
        # Test versions (1 or 2) and supported message types
        if ( m.version not in (1, 2) or 
             m.version == 1 and m.id not in (PUSH_DATA, PULL_DATA) or 
             m.version == 2 and m.id not in (PUSH_DATA, PULL_DATA, TX_ACK)
             ):
                print('Version',m.version,'ID',m.id)
                pass
                #raise UnsupportedMethod()

        # Decode gateway EUI and payload
        if m.id == PUSH_DATA:
            print('PUSH DATA')
            if len(data) < 12:
                raise DecodeError("PUSH_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]
            m.payload = data[12:]
        elif m.id == PULL_DATA:
            print('PULL DATA')
            if len(data) < 12:
                raise DecodeError("PULL_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]
            #print('Gateway EUI: ',m.gatewayEUI)
        elif m.id == TX_ACK:
            m.payload = data[4:]
            
        # Decode PUSH_DATA payload
        if m.id == PUSH_DATA:
            try:
                jdata = loads(m.payload)
            except ValueError:
                raise DecodeError("JSON payload decode error")
            m.ptype = list(jdata.keys())[0]
            # Rxpk payload - one or more.
            
            
            if  m.ptype == 'rxpk':
                m.rxpk = []
            
                for r in jdata['rxpk']:
                    rx = Rxpk.decode(r)
                    if rx is not None:
                        m.rxpk.append(rx)
                if not m.rxpk:
                    raise DecodeError("Rxpk payload decode error")
            
            # Stat payload
            elif m.ptype == 'stat':
                m.stat = Stat.decode(jdata)
                if m.stat is None:
                    raise DecodeError("Stat payload decode error")
            # Unknown payload type
            else:
                raise DecodeError("Unknown payload type")

        '''for a, v in m.__dict__.items():
            try:
                for attr, value in v.__dict__.items():
                    print('    '+attr,value)
            except:
                print(a, v)
                continue
        ''' 
        return m

    def encode(self):
        """Create a binary representation of message from Message object.
        
        Returns:
            String of packed data.
        
        """
        data = ''
        if self.id == PUSH_ACK:
            data = pack('<BHB', self.version, self.token, self.id)
        elif self.id == PULL_ACK:
            data = pack('<BHB', self.version, self.token, self.id)
        elif self.id == PULL_RESP:
            if self.version == 1:
                self.token = 0
            self.payload = self.txpk.encode()
            print(str(self.payload))
            data = pack('<BHB', self.version, self.token, self.id) + \
                    bytearray(self.payload,'utf-8')
        return data



def sendPullResponse(remote, request, txpk,sock):
    """"Send a PULL_RESP message to a gateway.
    
    The PULL_RESP message transports its payload, a JSON object,
    from the LoRa network server to the LoRa gateway. The length
    of a PULL_RESP message shall not exceed 1000 octets.
    
    Args:
        request (GatewayMessage): The decoded Pull Request
        txpk (Txpk): The txpk to be transported
    """
    remote = (remote[0], remote[1])

    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PULL_RESP, gatewayEUI=b'9079494338994186168',
                remote=remote, ptype='txpk', txpk=txpk)
    print("Sending PULL_RESP message to %s:%d" % remote)

    sock.sendto(m.encode(), remote)
    data, address = sock.recvfrom(4096)
    print(data)
    print('received %s bytes from %s' % (len(data), address))

def sendPushAck(remote, request,sock):
    """"Send a PULL_ACK message to a gateway.
    
   
    """
    remote = (remote[0], remote[1])

    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PUSH_ACK, gatewayEUI=b'9079494338994186168',
                remote=remote, ptype=None)
    print("Sending PULL_ACK message to %s:%d" % remote)

    sock.sendto(m.encode(), remote)


def sendPullAck(remote, request,sock):
    """"Send a PULL_ACK message to a gateway.
    
   
    """
    remote = (remote[0], remote[1])

    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PULL_ACK, gatewayEUI=b'9079494338994186168',
                remote=remote, ptype=None)
    print("Sending PULL_ACK message to %s:%d" % remote)
  
    sock.sendto(m.encode(), remote)

class Txpk(object):
    """A Gateway Txpk (downstream) JSON object.
    
    The root JSON object shall contain zero or more txpk
    objects. See Gateway to Server Interface Definition
    Section 6.2.4.
    
    Attributes:
        imme (bool): If true, the gateway is commanded to
                     transmit the frame immediately 
        tmst (int): If "imme" is not true and "tmst" is present,
                    the gateway is commanded to transmit the frame
                    when its internal timestamp counter equals the
                    value of "tmst".
        time (str): UTC time. The precision is one microsecond. The
                    format is ISO 8601 compact format. If "imme" is
                    false or not present and "tmst" is not present,
                    the gateway is commanded to transmit the frame at
                    this time.
        freq (float): The centre frequency on when the frame is to
                    be transmitted in units of MHz.
        rfch (int): The antenna on which the gateway is commanded
                    to transmit the frame.
        powe (int): The output power which what the gateway is
                    commanded to transmit the frame.
        modu (str): Modulation technique - "LORA" or "FSK".
        datr (str): Datarate identifier. For Lora, comprised of
                    "SFnBWm where n is the spreading factor and
                    m is the frame's bandwidth in kHz.
        codr (str): ECC code rate as "k/n" where k is carried
                    bits and n is total bits received.
        ipol (bool): If true, commands gateway to invert the
                    polarity of the transmitted bits. LoRa Server sets
                    value to true when "modu" equals "LORA", otherwise
                    the value is omitted.
        size (int): Number of octets in the received frame.
        data (str): Frame payload encoded in Base64. Padding characters
                    shall not be not added
        ncrc (bool): If not false, disable physical layer CRC generation
                    by the transmitter.
    """
    
    def __init__(self, imme=False, tmst=None, time=None, freq=None,
                 rfch=None, powe=None, modu=None, datr=None, codr=None,
                 ipol=None, size=None, data=None, ncrc=None):
        """Txpk initialisation method.
        
        """
        self.imme = imme
        self.tmst = tmst 
        self.time = time
        self.freq = freq
        self.rfch = rfch
        self.powe = powe
        self.modu = modu
        self.datr = datr
        self.codr = codr
        self.ipol = ipol  
        self.size = size
        self.data = data
        self.ncrc = ncrc
        self.keys = ['imme', 'tmst', 'time', 'freq', 'rfch',
                    'powe', 'modu', 'datr', 'codr', 'ipol',
                    'size', 'data', 'ncrc']
        # Base64 encode data, no padding
        if self.data is not None:
            self.size = len(self.data)
            self.data = b64encode(self.data)
            # Remove padding
            if self.data[-2:] == '==':
                self.data = self.data[:-2]
            elif self.data[-1:] == '=':
                self.data = self.data[:-1]
        else:
            self.size = 0
    
    def encode(self):
        """Create a JSON string from Txpk object
        
        """
        # Create dict from attributes. Maintain added order
        #jd = {'txpk': collections.OrderedDict()}
        jd = {'txpk':{}}

        for key in self.keys:
            val = getattr(self, key)

            if val is not None:
                if key == 'data':
                    jd['txpk'][key] = val.decode('utf-8')
                else:
                    jd['txpk'][key] = val
            #print('key',key)
            #print('valtype',type(val),val)                
        #print(jd)
        
        return dumps(jd, separators=(',', ':')) 


def intPackBytes(n, length, endian='big'):
    """Convert an integer to a packed binary string representation.
    
    Args:
        n (int: Integer to convert
        length (int): converted string length
        endian (st)r): endian type: 'big' or 'little'
    
    Returns:
        A packed binary string.
    """
    
    if length == 0:
        return ''
    h = '%x' % n
    # There must be a better way to do this
    s = unhexlify(str.zfill(('0'*(len(h) % 2) + h), length*2))
    if endian == 'big':
        return s
    else:
        #return s[::-1]
        
        return int.to_bytes(n, length, 'little')
    return n

def aesEncrypt(key, data, mode='CMAC'):
    """AES encryption function
    
    Args:
        key (str): packed 128 bit key
        data (str): packed plain text data
        mode (str): Optional mode specification (CMAC)
        
    Returns:
        Packed encrypted data string
    """
    dataorder='big'
    keyorder='big'
    
    if mode == 'CMAC':
        cipher = CMAC()
        # there must be a better way to do this
        key=(int.from_bytes(key[0:4], 'big'),
             int.from_bytes(key[4:8], 'big'),
             int.from_bytes(key[8:12], 'big'),
             int.from_bytes(key[12:16], 'big'))
        if len(data) <= 16:
            length=len(data)*8
            data=data+bytearray((16-len(data)))
            data=[(int.from_bytes(data[0:4], 'big'),
                   int.from_bytes(data[4:8], 'big'),
                   int.from_bytes(data[8:12], 'big'),
                   int.from_bytes(data[12:16], 'big'))]
        elif len(data) > 16:
            length = (len(data)-16)*8
            data=data+bytearray((32-len(data)))
            data=[(int.from_bytes(data[0:4], 'big'),
                   int.from_bytes(data[4:8], 'big'),
                   int.from_bytes(data[8:12], 'big'),
                   int.from_bytes(data[12:16], 'big')),
                  (int.from_bytes(data[16:20], 'big'),
                   int.from_bytes(data[20:24], 'big'),
                   int.from_bytes(data[24:28], 'big'),
                   int.from_bytes(data[28:32], 'big'))]          
        else:
            print('Data greater than 32 bytes')
        mic=cipher.cmac(key, data, length)  
        mic = mic[0].to_bytes(4, 'big')
        return mic
        
    else: 
        try: 
            cipher = AES.new(key,AES.MODE_ECB)
        except:
            cipher = AES(key,AES.MODE_ECB)
        return cipher.encrypt(data)

def buildJoinRequest(dev_eui,app_eui,dev_nonce,app_key):
    data=bytes([0x00])+app_eui+dev_eui+dev_nonce
    mic = aesEncrypt(intPackBytes(app_key, 16), data,
                     mode='CMAC')[0:4]
    return data+mic


APP_KEY=0x00000000000000000000000000000000
APP_EUI=0x0000000000000000
DEV_EUI=0x0000000000000000

def main():
    try:
        f = open('nonce.txt', 'r')
        DEV_NONCE = int(f.readline()) # can be used only once and it appears Helium console drops packets with repeated dev nonce
    except:
        DEV_NONCE = 0x0000
        f=open('nonce.txt', 'w')
        f.write(str(DEV_NONCE))
        f.close()    
        
    app_key=APP_KEY
    app_eui=intPackBytes(APP_EUI,8)
    dev_eui=intPackBytes(DEV_EUI,8)
    dev_nonce=int(DEV_NONCE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    server_address = ('', 1680)
    print('Starting up on%s port %s' % server_address)
    sock.bind(server_address)

    while True:
        print('\n===================================================================')
        data, remote = sock.recvfrom(4096)
        print('received %s bytes from %s' % (len(data), remote))

        # Decode the data from the gateway even though we don't really care        
        gm=GatewayMessage()
        message = gm.decode(data, remote)

        # build data payload for OTAA join
        packet=hexlify(buildJoinRequest(dev_eui,app_eui,intPackBytes(dev_nonce,2),app_key))

        if message.id==PULL_DATA:

            txpk = Txpk(imme=True, freq=904.3,
                                   rfch=0, powe=27,
                                   modu="LORA", datr='SF10BW125',
                                   codr="4/5", ipol=False, ncrc=False, data=unhexlify(packet))
            sendPullResponse(remote,message,txpk, sock)

            # update the nonce and write it to file
            f=open('nonce.txt', 'w')
            dev_nonce=dev_nonce+1
            f.write(str(dev_nonce))
            f.close() 
            
        elif message.id==PUSH_DATA:
            sendPushAck(remote, message,sock)
        
        
if __name__ == "__main__":
    main()

    
