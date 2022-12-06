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
  def __init__(self,Sock_1,Sock_2,mode,AES_K):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
    self.mode=mode
    self.AES_K=AES_K

  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
        #SafePost=Encipher(Post)
        if self.mode==SEND:
          SafePost=encrypt.MyRSAEncrypt(Post,self.AES_K)
        else: 
          SafePost=encrypt.MyRSADecrypt(Post,self.AES_K)
        self.SendSock.send(SafePost)
      except BrokenPipeError:
        pass
      except ConnectionResetError:
        pass
    
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

    Status,RemotePort,Length,AES_K=struct.unpack("!BHB16s",Post[:20])
    print("recieve ASE_K",AES_K)
    url=struct.unpack("!"+str(Length)+'s',Post[20:])[0]
    RemoteAddress=socket.gethostbyname(url)
    print("Connecting",url,RemoteAddress)

    if Status == TCP:
      try:
        RemoteSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        RemoteSock.connect((RemoteAddress,RemotePort))
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
      SendThread=PostTransmitter(self.ClientSock,RemoteSock,RECEIVE,AES_K)
      AcceptThread=PostTransmitter(RemoteSock,self.ClientSock,SEND,AES_K)
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
