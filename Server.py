import socket
import struct
import threading
import os
import json
import encrypt

# Define 4 status of the HandShake period.
REFUSED=0 # Connection denied by this server.
TCP=1 # Build TCP connection with the remoteserver
UDP=2 # Build UDP association with the remoteserver
BIND=3 # Reversed Link (Not implemented yet)

MAX_BUFFER=4096 # The max size of the post recieved
MAX_CLIENT=3 # Maximum waiting clients num

SEND=0
RECEIVE=1

Method=0 # Authentacation method.
# 0 represents no authentacation
# 2 represents Username-Password
Username=''
Passwd=''

def Encipher(Post):
  CipheredPost=b''
  Key = 0x3c
  for byte in Post:
    Cipheredbyte=byte^Key
    CipheredPost+=bytes((Cipheredbyte,))
  return CipheredPost


class PostTransmitter(threading.Thread):
  '''
  Recieve post from a socket,and transmit it to another.
  '''
  def __init__(self,Sock_1,Sock_2,mode):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
    self.mode=mode 

  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
        #SafePost=Encipher(Post)
        if self.mode==SEND:
          SafePost=encrypt.MyAESencrypt(Post)
        else: 
          SafePost=encrypt.MyAESdecrypt(Post)
        self.SendSock.send(SafePost)
      except BrokenPipeError:
        pass
      except ConnectionResetError:
        pass


def HandShake(Post):
  '''
  Handle the handshake period of server and client.
  ''' 
    # +-----+----------+----------+
    # | VER | NMETHODS | METHODS  |
    # +-----+----------+----------+
    # |  1  |    1     |  1~255   |
    # +-----+----------+----------+
  Version,MethodNum = struct.unpack('!BB',Post[:2])
  Post=Post[2:]
  Format='!'
  for i in range(0,MethodNum):
    Format+='B'
  Methods = struct.unpack(Format,Post)
  if 0 in Methods:
    AcceptMethod=0x00 
  else:
    AcceptMethod=0xff
    # If client doesn't support no authentacation mode, refuse its request.
  Answer=struct.pack('!BB',Version,AcceptMethod)
  return Answer

def Verify(Post):
  Version,ULen=struct.unpack('!BB',Post[:2])
  Uname,PLen=struct.unpack('!'+str(ULen)+"sB",Post[2:3+ULen])
  Pw,=struct.unpack('!'+str(PLen)+'s',Post[3+ULen:])
  if Uname == bytes(Username,encoding='utf-8') and Pw == bytes(Passwd,encoding='utf-8'):
    reply=0x00
  else:
    reply=0xff
  Answer=struct.pack('!BB',Version,reply)
  return Answer

def Connect(Post):
  '''
  The second handshake with client.
  '''
  
  PostInfo={}
  if Post != b'':
    PostInfo['Version'],PostInfo['Command'],PostInfo['RSV'],PostInfo['AddrType']\
    = struct.unpack('!BBBB',Post[:4])

  # AddressType:
  # 0x01 - IPv4
  # 0x03 - DomainName (not supported)
  # 0x04 - IPv6
  if PostInfo['AddrType'] == 0x01:
    Length=4
    # Parse RemoteServer's address by AddrType
    Format='!'+str(Length)+'sH'
    RawAddress,PostInfo['RemotePort']=struct.unpack(Format,Post[4:])
    PostInfo['RemoteAddress']=socket.inet_ntoa(RawAddress)
  else:
    print('Error: Wrong address type.')
    PostInfo['REP']=0x08
    return (PostInfo,REFUSED)

  # Respond to Client's Command.
  if PostInfo['Command'] == 0x01:
    PostInfo['REP']=0x00
    return (PostInfo,TCP)
  else:
    PostInfo['REP']=0x02
    return (PostInfo,REFUSED)
    
class TCPHandler(threading.Thread):
  '''
  Communicate with one single Client.
  '''
  def __init__(self,ClientSock):
    threading.Thread.__init__(self)
    self.ClientSock=ClientSock
  def run(self):
    '''if Method == 2:
      Post=self.ClientSock.recv(MAX_BUFFER)
      self.ClientSock.send(Verify(Post))'''
    # First Handshake
    '''RawPost=self.ClientSock.recv(MAX_BUFFER)
    Post=Encipher(RawPost)
    self.ClientSock.send(Encipher(HandShake(Post)))'''
    # Second Handshake,gain information.
    Post=self.ClientSock.recv(MAX_BUFFER)
    #Post=Encipher(RawPost)
    #PostInfo,Status=Connect(Post)
    Status,RawAddress,RemotePort=struct.unpack("!B4s",Post)
    RemoteAddress=socket.inet_ntoa(RawAddress)

    if Status == TCP:
      try:
        RemoteSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        RemoteSock.connect(RemoteAddress,RemotePort)
      except ConnectionRefusedError:
        print('Error: Connection refused.')
        RemoteSock.close()
        Status=REFUSED

    # Judge Status
    if Status == REFUSED:
      # If server refuses client's request,send the answer and close the socket.
      print('Request refused.')
      Answer=struct.pack('!B',0)
      self.ClientSock.send(Answer)
      self.ClientSock.close()
      return
    else:
      # Assemble the answer
      Answer=struct.pack('!B',1)
      self.ClientSock.send(Answer)
      SendThread=PostTransmitter(self.ClientSock,RemoteSock,RECEIVE)
      AcceptThread=PostTransmitter(RemoteSock,self.ClientSock,SEND)
      SendThread.start()
      AcceptThread.start()
      # RAM leakage warning
      return


if __name__ == '__main__':
  ServerSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  print('Welcome !\n')
  ConfigFile=open("./ServerConfig.json","r")
  Config=json.load(ConfigFile)
  try:
    Address=Config['BindIP']
    Port=Config['BindPort']
    Method=Config['Method']
    Username=Config['Username']
    Passwd=Config['Password']
  except KeyError:
    print('Config information error. Please check your config file.')
    os.sys.exit()

  print("\nWaiting for connection ...\n")
  try:
    ServerSock.bind((Address,int(Port)))
    ServerSock.listen(MAX_CLIENT)
    while True:
      CliSock,CliAddr=ServerSock.accept()
      Thread=TCPHandler(CliSock)
      Thread.start()
  except OSError:
    print("Error: Address already in use. Please use another port.")
    os.sys.exit()
  except KeyboardInterrupt:
    print('\n\nbye bye.\n')
    os.sys.exit()
  finally:
    ServerSock.close()
