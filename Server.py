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

class PostTransmitter(threading.Thread):
  '''
  Recieve post from a socket,and transmit it to another.
  '''
  def __init__(self,Sock_1,Sock_2,mode,OtherPub,AES_K):
    threading.Thread.__init__(self)
    self.AcceptSock=Sock_1
    self.SendSock=Sock_2
    self.mode=mode
    self.OtherPub=OtherPub
    self.AES_K=AES_K

  def run(self):
    while True:
      try:
        Post=self.AcceptSock.recv(MAX_BUFFER)
        #SafePost=Encipher(Post)
        if self.mode==SEND:
          SafePost=encrypt.MyFullEncrypt(Post,self.AES_K)
        else: 
          SafePost,valid=encrypt.MyFullDecrypt(Post,self.OtherPub,self.AES_K)
          if not valid:
            print("signature invalid")
            self.SendSock.close()
            self.AcceptSock.close()
            return
        self.SendSock.send(SafePost)
      except BrokenPipeError:
        pass
      except ConnectionResetError:
        pass
      finally:
        return
    
class TCPHandler(threading.Thread):
  '''
  Communicate with one single Client.
  '''
  def __init__(self,ClientSock):
    threading.Thread.__init__(self)
    self.ClientSock=ClientSock
  def run(self):
    Post=self.ClientSock.recv(MAX_BUFFER)
    Post=encrypt.MyRSAdecrypt(Post)

    Status,RemotePort,Length,PubLen,AES_K=struct.unpack("!BHBH16s",Post[:22])
    if not verified:
      Status=REFUSED
    print("recieve ASE_K",AES_K)
    url=struct.unpack("!"+str(Length)+'s',Post[22:22+Length])[0]
    Post=Post[22+Length:]
    Version,ULen=struct.unpack('!BB',Post[:2])
    Uname,PLen=struct.unpack('!'+str(ULen)+"sB",Post[2:3+ULen])
    Pw,=struct.unpack('!'+str(PLen)+'s',Post[3+ULen:])
    if Uname == bytes(Username,encoding='utf-8') and Pw == bytes(Passwd,encoding='utf-8'):
      verified=True
      print("id verified")
    else:
      verified=False
      print("id not verified")

    PubKey=open('other.pem','r').read().encode('utf-8')
    print(PubKey)
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
      SendThread=PostTransmitter(self.ClientSock,RemoteSock,RECEIVE,PubKey,AES_K)
      AcceptThread=PostTransmitter(RemoteSock,self.ClientSock,SEND,PubKey,AES_K)
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
