/*
 *  $Id$
 *
 *  Vadim Zaliva <lord@crocodile.org>
 *  http://www.crocodile.org/
 *
 *  Copyright (C) 1999 Vadim Zaliva
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

struct Dict
{
    char  *name;
    char **value;
    int    nvalues;
};

struct Cfg
{
    struct Dict **dict;
    int    nelements ;
};

struct Cfg *readcfg   (const char *filename);
int         writecfg  (const char * filename, struct Cfg *);
char       *cfgfind   (const char *,struct Cfg *, int offset);
void        freecfg   (struct Cfg *);
struct Cfg *newcfg    ();
void        sortcfg   (struct Cfg *);
void        cfg_add_entry (struct Cfg *, struct Dict *);

/* convinience functions */
void        cfg_new_entry (struct Cfg *cfg, const char *name, ...);
void        cfg_new_ulong_entry (struct Cfg *cfg, const char *name, unsigned long v);
void        cfg_new_fmt_ulong_entry (struct Cfg *cfg, const char *name, unsigned long v, int w);


