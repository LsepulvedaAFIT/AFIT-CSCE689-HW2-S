#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <ctime>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {
   //seeds the random generator with the time
   srand(time(NULL));   

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   //creates empty container to used the find user
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {
   //container that stores the hashed passwd
   std::vector<uint8_t> ret_hash{};
   std::vector<uint8_t> ret_salt{};
   //std::vector<uint8_t> in_salt{1,7,7,5,7,1,3,6,1,5,4,5,7,5,4,9};//testing
   std::vector<uint8_t> in_salt{};
   
   // Insert your insane code here
   //Keeps track of where it needs to overwrite passwd file
   int offset = 0;

   //opens password file to find user, hash, & salt
   FileFD pwfile(_pwd_file.c_str());
   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   bool eof = false;
   
   //Find the name in passwd file ans stores the location in the file in offset variable
   while (!eof) {
      ret_hash.clear();
      in_salt.clear();
      std::string tempBuffer;
      ssize_t bytes = pwfile.readStr(tempBuffer);
      offset = offset + bytes + 1;

      if (tempBuffer.size() == 0) {
         eof = true;
         continue;
      }

      if (!tempBuffer.compare(name)) {
         pwfile.closeFD();
         break;
      }
      pwfile.readBytes(ret_hash, 32);
      pwfile.readBytes(in_salt, 16);
      offset = offset + 48;
      tempBuffer.clear();
      pwfile.readStr(tempBuffer);
      offset = offset + 1;
   }

   //Hashes the new passwd and creates new salt
   ret_hash.clear();
   hashArgon2(ret_hash, ret_salt, passwd, &in_salt);

   pwfile.closeFD();

   //opens file to write new hash and salt
   FileFD pwfile2(_pwd_file.c_str());
   if (!pwfile2.openFile(FileFD::writefd))
      throw pwfile_error("Could not open passwd file for reading");

   int fd = pwfile2.getFD();

   //goes to the location of of the previos user hash
   lseek(fd, offset, SEEK_SET);

   //overwrites exiting hash and salt with the new 
   int writeResult = writeHash(pwfile2, ret_hash, ret_salt);

   pwfile2.closeFD();

   if (writeResult == 0){
      return false;
   }

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{

   // Insert your perfect code here!
   //checks if it is the end of file
   if (pwfile.readStr(name) == 0){
      return false;
   }   
   
   std::string tempString;

   //reads hash & salt 
   pwfile.readBytes(hash, 32);
   pwfile.readBytes(salt, 16);
   pwfile.readStr(tempString);

   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   //writes the name, hash, and salt
   int results;
   results = pwfile.writeFD(name);
   results = pwfile.writeFD("\n");
   results = pwfile.writeBytes(hash);
   results = pwfile.writeBytes(salt);
   results = pwfile.writeFD("\n");

   return results; 
}

int PasswdMgr::writeHash(FileFD &pwfile, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   //writes hash and salt
   int results;
   results = pwfile.writeBytes(hash);
   results = pwfile.writeBytes(salt);
   results = pwfile.writeFD("\n");

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   //open passwd file for reading
   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   // reads file until the find the specified name
   bool eof = false;
   while (!eof) {
      std::string uname{};

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
   //code based off usage example at https://github.com/P-H-C/phc-winner-argon2
   int HASHLEN = 32;
   int SALTLEN = 16;

   uint8_t hash1[HASHLEN];

   uint8_t salt[SALTLEN];
   memset( salt, 0x00, SALTLEN );

   //checks if new salt is needs to be created
   if (in_salt->empty())
   {
      ret_salt.clear();
      //creates salt
      for (int i = 0; i < 16; i++){
         int randomNum = rand() % 30;
         ret_salt.push_back(randomNum);
         salt[i] = randomNum;
      }
   }
   else
   {
      for (int i = 0; i < 16; i++){
         salt[i] = in_salt->at(i);
      }
   }

   //convert char * to uint8_t as needed for argon2 function
   uint8_t *pwd = (uint8_t *)strdup(in_passwd);
   uint32_t pwdlen = strlen((char *)pwd);

   uint32_t t_cost = 2;            // 1-pass computation
   uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
   uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
   //argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, in_salt, SALTLEN, hash1, HASHLEN);
   argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

   //pushing returned hash in to vector container
   for (int i = 0; i < 32; i++){
      ret_hash.push_back(hash1[i]);
   }

   //delete created memory
   delete pwd;

}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   //coverts name to string for easier processing
   std::string nameStr(name);

   // Add those users!
   std::vector<uint8_t> ret_hash;
   std::vector<uint8_t> ret_salt;
   //std::vector<uint8_t> in_salt{1,7,7,5,7,1,3,6,1,5,4,5,7,5,4,9};//Testing
   std::vector<uint8_t> in_salt{};

   //creates a random 16 byte salt
   for (int i = 0; i < 16; i++){
      int randomNum = rand() % 30;
      in_salt.push_back(randomNum);
   }
   
   //hashes passwd with Argon2 function
   hashArgon2(ret_hash, ret_salt, passwd, &in_salt);
   
   //adding username, passwd, and salt to file
   FileFD pwfile(_pwd_file.c_str());

   //error checking that file open
   if (!pwfile.openFile(FileFD::appendfd))
      throw pwfile_error("Could not open passwd file for reading");

   
   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   writeUser(pwfile, nameStr, ret_hash, in_salt);

   pwfile.closeFD();
   
}

