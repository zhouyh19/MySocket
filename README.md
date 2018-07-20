> ## A Proxy Based On SOCK5

	This is a simple proxy program under linux platform.
	
***

## Usage

1. Clone or download this repository
2. Edit ServerConfig.json and ClientConfig.json
    - __The format is important__. __Donot__ change __the file's name__ or __labels' names__.
    - The format is as follow:

    ```

    ClientConfig.json:
    {
      "RemoteIP":"",    # The IP address of your VPS on where you run server.py
      "RemotePort":,    # Choose a Port same as "BindPort" in ServerConfig.json
      "LocalIP":"",     # Usually 127.0.0.1
      "LocalPort":,     # Choose a free port you want to bind with.
      "Username":"",    # Used for identification.
      "Password":"",
      "Method":         # An integer which represents authentacation method. 0 for non-authentacation, 2 for Username-Password identification.
    }
    ServerConfig.json:
    {
      "BindIP":"",      # Usually 0.0.0.0
      "BindPort":,      # Choose a Port same as "RemotePort" in ClientConfig.json
      "Username":"",    # Used for identification.
      "Password":"",
      "Method":         # An integer which represents authentacation method. 0 for non-authentacation, 2 for Username-Password identification.
    }

    ```

    - By the way, if you don't want to edit these config files, you may delete them and input these information every time you run this program. :)
    
3. Install an proxy addup (like `SwitchyOmega`) on your Explorer. Set the proxy server's IP address as "LocalIP" and set it's port as "LocalPort" in ClientConfig.json.
4. __Make sure that your python is python3__.
    - You may execute `python -V` to check the version of your python.
5. Execute `python Server.py` on your VPS and `python Client.py` on your device.
6. Enjoy! :)


## Features

* The data has been enciphered, though the method is far too simple. You may change the Encipher() function to increase the security.
* You may pick an authentacation method as you like. Just change the content of "Method" label in json files.

