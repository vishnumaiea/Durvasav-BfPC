
/*  sha1.c - subfile of main.c of Durvasav 9.3.1  */
/*  OpenSSL implementation                        */
/*  13/02/13 22:47                                */

/*************************************************
	Name: Durvasav
	Version: 3.2.1.0
	Description: Bruteforce Password Cracker (BfPC)
	Author: Vishnu M Aiea (AYGENT543)
	Date: 12/02/13 23:19
	Copyright: Copyright (c) 2013 Vishnu M Aiea
	Contact: vishnumaiea@gmail.com
	Website : www.vishnumaiea.in
	License: GNU GENERAL PUBLIC LICENSE	version 3
**************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
 
void SHA1_Convert(register char *string,register char *hashout, register int len)
{
  register int i;
  unsigned char result[20];
 
  SHA1(string, len, result);
 
  for(i = 0; i < 20; i++)
  {
      sprintf(&hashout[i*2],"%02x", result[i]);
  }
}

