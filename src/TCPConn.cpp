#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"
#include "PasswdMgr.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";

TCPConn::TCPConn(){ // LogMgr &server_log):_server_log(server_log) {
   this->PWMgr = std::make_unique<PasswdMgr>(pwdfilename);
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {
   //initializes attempts to zero
   this->_pwd_attempts = 0;
   //transition username state
   _status = s_username;
   //client console output
   _connfd.writeFD("Username: "); 

}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   //testing
   //std::cout << "_status: " << _status << std::endl;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here
   //Check if user has inputed name
   if (!_connfd.hasData())
      return;
   std::string userNameInput;
   if (!getUserInput(userNameInput))
      return;

   //store name (case-sensitive) in object
   this->_username = userNameInput;   
   //std::cout << "Got User Name: " << _username << std::endl;//testing

   if (!PWMgr->checkUser(this->_username.c_str()) )
   {
      sendText("Username not recognized\n");
      //Logs message with client IP address & disconnects
      log(usrName_NOT_recog);
      disconnect();
      //Server terminal message for Admin notification
      std::cout << "Username not found: disconnected client" << std::endl;
   }
   else{
      //Server terminal message for Admin notification
      std::cout << "Username found" << std::endl;
   }
   //transitions to password state
   _connfd.writeFD("Password: "); 
   this->_status = s_passwd;

}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your mind-blowing code here
   //Check if user has inputed passwd
   if (!_connfd.hasData())
      return;
   std::string userPasswdInput;
   if (!getUserInput(userPasswdInput))
      return;

   //checks if password is correct
   bool validPW = this->PWMgr->checkPasswd(this->_username.c_str(), userPasswdInput.c_str());

   if (!validPW)
   {
      std::cout << "invalid password" << std::endl;
      _connfd.writeFD("Invalid Password\n"); 
      this->_pwd_attempts++;
      if (this->_pwd_attempts == 2 ){
         //logs fail attempts
         log(paswd_failed_twice);
         _connfd.writeFD("Too many login attempts\n"); 
         disconnect();
      }
      _connfd.writeFD("Password: "); 
   }
   else{
      std::cout << "Password verified" << std::endl;
      log(succ_login);
      _connfd.writeFD("Log in successful\n");
      this->_status = s_menu;
   }
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here
   //
   if (!_connfd.hasData())
      return;
   std::string newPasswdInput;
   if (!getUserInput(newPasswdInput))
      return;


   //Calls PasswdMgr function w/ error handling
   if (!this->PWMgr->changePasswd(this->_username.c_str(), newPasswdInput.c_str()) )
   {
      _connfd.writeFD("Password change error occured\n");
      _connfd.writeFD("Type \"passwd\" to try again\n");
   }

   //Confirmation message to client
   _connfd.writeFD("Password successfully changed\n");

   //Transitions to menu state
   this->_status = s_menu;

}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "You want a prediction about the weather? You're asking the wrong Phil.\n";
      msg += "I'm going to give you a prediction about this winter. It's going to be\n";
      msg += "cold, it's going to be dark and it's going to last you for the rest of\n";
      msg += "your lives!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("42\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("That seems like a terrible idea.\n");
   } else if (cmd.compare("4") == 0) {

   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("I'm singing, I'm in a computer and I'm siiiingiiiing! I'm in a\n");
      _connfd.writeFD("computer and I'm siiiiiiinnnggiiinnggg!\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Available choices: \n";
   menustr += "  1). Provide weather report.\n";
   menustr += "  2). Learn the secret of the universe.\n";
   menustr += "  3). Play global thermonuclear war\n";
   menustr += "  4). Do nothing.\n";
   menustr += "  5). Sing. Sing a song. Make it simple, to last the whole day long.\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   //logs disconnetion
   log(discon);
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

bool TCPConn::isNewIPAllowed(std::string inputIP){
   std::ifstream whitelistFile("whitelist");
   if(!whitelistFile){
      std::cout << "whitelist file not found" << std::endl;
      return false;
   }
   
   if (whitelistFile.is_open()){
      std::string line;
      while(whitelistFile >> line){
         //std::cout << "IP: " << inputIP << ", line: " << line << std::endl;//
         if (inputIP == line){
            std::cout << "New connection IP: "<< inputIP << " , authorized from whitelist" << std::endl;
            return true;
         }
      }
   }

   std::cout << "Match NOT FOUND!" << std::endl;
   return false;

}

void TCPConn::log(std::string logString){

   std::string logFileName = "server.log";

   FileFD logFile(logFileName.c_str());

   if (!logFile.openFile(FileFD::appendfd))
      throw pwfile_error("Could not open log file for writing");

   logFile.writeFD(logString);

   // current date/time based on current system
   time_t now = time(0);
   
   // convert now to string form
   char* date_Time = ctime(&now);

   logFile.writeFD(" ");
   logFile.writeFD(date_Time);

   logFile.closeFD();
}

void TCPConn::log(std::string ipAddress, enum logMessage inputLogOption){
   std::stringstream ss;

   switch (inputLogOption){

      case newConn_NOT_WL:
         ss << "IP address \"" << ipAddress << "\" NOT on whitelist attempted to connect,";
         break;

      case newConn_ON_WL:
         ss << "IP address \"" << ipAddress << "\" on whitelist connected,";
         break;

      default:
         ss << "";
         break;
   }

   log(ss.str());


}


void TCPConn::log(enum logMessage inputLogOption){

   std::stringstream ss;

   std::string IPAddress;
   this->getIPAddrStr(IPAddress);

   switch (inputLogOption)
   {
      case serverStart:
         ss << "Server started, ";
         break;

      case usrName_NOT_recog:
         ss << "Username \"" << _username << "\" NOT recognized, " << "IP: \"" << IPAddress << ",\"";
         break;

      case paswd_failed_twice:
         ss << "Username \"" << _username << "\" failed to password twice, " << "IP: \"" << IPAddress << "\"";
         break;
      
      case succ_login:
         ss << "Username \"" << _username << "\" succesful login, " << "IP: \"" << IPAddress << "\"";
         break;
      
      case discon:
         ss << "Username \"" << _username << "\" disconnected, " << "IP: \"" << IPAddress << "\"";
         break;

      default:
         ss << "";
         break;
   }

   //std::string logString(ss.str());

   log(ss.str());
}
