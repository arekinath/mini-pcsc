/* iso7816.h - ISO 7816 commands
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ISO7816_H
#define ISO7816_H

/* Command codes used by iso7816_check_pinpad. */
#define ISO7816_VERIFY                0x20
#define ISO7816_CHANGE_REFERENCE_DATA 0x24
#define ISO7816_RESET_RETRY_COUNTER   0x2C


/* Information to be passed to pinpad equipped readers.  See
   ccid-driver.c for details. */
struct pininfo_s
{
  int fixedlen;  /*
		  * -1: Variable length input is not supported,
		  *     no information of fixed length yet.
		  *  0: Use variable length input.
		  * >0: Fixed length of PIN.
		  */
  int minlen;
  int maxlen;
};
typedef struct pininfo_s pininfo_t;

#endif /*ISO7816_H*/
