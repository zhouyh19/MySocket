import socket
import struct
import threading
import os
import json

# Define 4 status of the HandShake period.
REFUSED=0 # Connection denied by this server.
TCP=1 # Build TCP connection with the remoteserver
UDP=2 # Build UDP association with the remoteserver
BIND=3 # Reversed Link (Not implemented yet)

MAX_BUFFER=4096 # The max size of the post recieved
MAX_CLIENT=3 # Maximum waiting clients num

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

class PostTransmitter(threading.Thread):
  '''
  Recieve post from a socket,and transmit it to another.
  '''
  def __init__(self,Sock_1,Sock_2):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
        SafePost=Encipher(Post)
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
    
    RawPost=self.ClientSock.recv(MAX_BUFFER)
    #Post=Encipher(RawPost)
    self.ClientSock.send(HandShake(RawPost))

    SendThread=PostTransmitter(self.ClientSock,self.RemoteSock)
    AcceptThread=PostTransmitter(self.RemoteSock,self.ClientSock)
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