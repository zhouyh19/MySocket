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

def Construct():
  ULen=len(Username)
  PLen=len(Passwd)
  UName=bytes(Username,encoding='utf-8')
  Pw=bytes(Passwd,encoding='utf-8')
  Post=struct.pack("!BB"+str(ULen)+"sB"+str(PLen)+"s",0x05,ULen,UName,PLen,Pw)
  return Post

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
  print("handshake!")
  return Answer

def Connect(Post,RemoteSock):
  PostInfo={}
  PostInfo['Version'],PostInfo['Command'],PostInfo['RSV'],PostInfo['AddrType'] = struct.unpack('!BBBB',Post[:4])
  
  if PostInfo['AddrType'] == 0x01:
    
    # Parse RemoteServer's address by AddrType
    Format='!4sH'
    PostInfo['RawAddress'],PostInfo['RemotePort']=struct.unpack(Format,Post[4:])
    PostInfo['RemoteAddress']=socket.inet_ntoa(PostInfo['RawAddress'])
    print(PostInfo['RemoteAddress'],type(PostInfo['RawAddress']),type(PostInfo['RemoteAddress']))
  else:
    print('Error: Wrong address type.')
    PostInfo['REP']=0x08
    PostInfo['RawAddress']=b''
    PostInfo["RemotePort"]=0
    return (PostInfo,REFUSED)

  if PostInfo['Command'] == 0x01:
    PostInfo['REP']=0x00
    return (PostInfo,TCP)
  else:
    PostInfo['REP']=0x02
    return (PostInfo,REFUSED)

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


class TCPHandler(threading.Thread):
  '''
  Communicate with one single Client.
  '''
  def __init__(self,ClientSock,RemoteAddress,RemotePort):
    threading.Thread.__init__(self)
    self.ClientSock=ClientSock
    try:
      self.RemoteSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      self.RemoteSock.connect((RemoteAddress,RemotePort))
    except:
      print('Some error occured.')
  def run(self):
    '''if Method == 2:
      Request=Construct()
      self.RemoteSock.send(Request)
      Answer=self.RemoteSock.recv(MAX_BUFFER)
      if Answer != b'\x05\x00':
        print('Invalid Username or wrong password.')
        os.sys.exit()'''
    
    Post=self.ClientSock.recv(MAX_BUFFER)
    #Post=Encipher(RawPost)
    self.ClientSock.send(HandShake(Post))

    Post=self.ClientSock.recv(MAX_BUFFER)
    PostInfo,status=Connect(Post,self.RemoteSock)
    
    Post=struct.pack("!B4sH",status,PostInfo["RawAddress"],PostInfo["RemotePort"])
    self.RemoteSock.send(Post)
    Post=self.RemoteSock.recv(MAX_BUFFER)

    Success=struct.unpack("!B",Post)

    if Success==0:
      Answer=struct.pack('!BBBB',\
      PostInfo['Version'],PostInfo['REP'],PostInfo['RSV'],PostInfo['AddrType'])
    
    else: 
      Answer=struct.pack('!BBBB4sH',\
      PostInfo['Version'],PostInfo['REP'],PostInfo['RSV'],PostInfo['AddrType'],\
      socket.inet_aton(PostInfo['RemoteAddress']),PostInfo['RemotePort'])

    self.ClientSock.send(Answer)
    if Success==0:
      self.ClientSock.close()
      return

    SendThread=PostTransmitter(self.ClientSock,self.RemoteSock,SEND)
    AcceptThread=PostTransmitter(self.RemoteSock,self.ClientSock,RECEIVE)
    SendThread.start()
    AcceptThread.start()

if __name__ == '__main__':
  ServerSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  print('Welcome !\n')
  ConfigFile=open("./ClientConfig.json","r")
  Config=json.load(ConfigFile)
  
  try:
    Address=Config['LocalIP']
    Port=Config['LocalPort']
    RemoteAddress=Config['RemoteIP']
    RemotePort=Config['RemotePort']
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
      Thread=TCPHandler(CliSock,RemoteAddress,int(RemotePort))
      Thread.start()
  except OSError:
    print("Error: Address already in use. Please use another port.")
    os.sys.exit()
  except KeyboardInterrupt:
    print('\n\nbye bye.\n')
    os.sys.exit()
  finally:
    ServerSock.close()