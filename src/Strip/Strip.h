/*
Program : Strip (Secure Tool for Recalling Important Passwords) 
Description: A secure password and account manager for the Palm(t) Computing Platform 
Copyright (C) 1999  Stephen J Lombardo

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

Strip has been written and developed by Stephen J Lombardo (Zetetic Enterprises) 1999

Contact Info:
lombardos@zetetic.net
http://www.zetetic.net/
Zetetic Enterprises
348 Wasington Ave 
Clifton NJ, 07011

Bug reports and feature requests should be sent to bugs@zetetic.net.


------RSA Data Security, Inc. MD5 Message Digest Algorithm-------------
Strip uses the MD5 message digest algorithm, Copyright (C) 1990, 
RSA Data Security, Inc. All rights reserved. See md5.c or md5.h 
for specific terms and warranty disclaimer from RSA Data Security Inc.
-----------------------------------------------------------------------


------Idea block encryption---------------------------------------
Strip uses the Idea block encryption algoritm, Copyright (C) Ascom. All rights reserved.
Idea is a patented algorithm. It is free for non commercial use, if you wish to use 
this product or the Idea algorithm in general for commercial purposes, you must purchase a license
from Ascom at http://www.ascom.ch/infosec/idea/pricing.html
-----------------------------------------------------------------------

        <**  DO NOT EXPORT **>
Strip uses strong cryptography. "Idea" is a block algoritm with a
128 bit key length, and "MD5" creates a 128 bit message digest. In the 
United states it is currently illegal to export products describing
or incorporating encryption techniques with key lengths greater
than 40 bits. It is therefore illegal to export this program in
any format. Please dont get the government on my back...
*/  

#ifndef STRIP_H
#define STRIP_H

#include "types.h"
#include "strip_types.h"

/*	Function prototypes */


#define  STR_FIRSTTIME	"This is the first time you are using Strip. " \
							 					"The password you enter at the prompt will become the new Strip password."

#define  STR_EVAL_START 	"You have been using this program for "	
#define  STR_EVAL_END " days. Registration will eliminate this " \
											"screen and also entitles you to " \
											"other benefits. Please visit www.zetetic.net for more information."

#define STR_INCORRECT_PASSWORD "The password you entered is incorrect."
#define STR_PASSWORDS_DONT_MATCH "New passwords do not match!"
#define STR_UNFILED_CATEGORY "Unfiled"
#define STR_ACCOUNT_DELIM ": "
#define STR_EOS "\0"
#define STR_WRONGVERSION "It looks like you have not run the StripCS program "\
			 										"to update your databases. Please install and run StripCS before running "\
													"this version of Strip."
#define STR_BADREGCODE	"The Email address or Registration Code you entered is invalid."
#define STR_EMPTY	""
#define STR_EMPTY_PASSWORD "You forgot to enter a password."
#define STR_EMPTY_USERNAME "You must enter a Login."
#define STR_REGEN_ALERT "If you regenerate the signature of this account " \
			" it will affect your ability to synchronize it with other users via IR SmartBeaming." \
			" Are you sure you want to regenerate the signatures on this account? "

#define STR_REGEN_ALL_ALERT "If you regenerate account signatures it may" \
			" affect your ability to synchronize accounts with other users via IR SmartBeaming." \
			" Are you sure you want to regenerate the signatures on all your accounts? "

#endif
