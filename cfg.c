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

#include "cfg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>

#define MAXTOKENLEN 1024

static int cfg_entry_cmp(const void *a,const void *b)
{
    return(strcmp((*((struct Dict **)a))->name, (*((struct Dict **)b))->name));
}

static int cfg_entry_match(const void *a,const void *b)
{
    return(strcmp((const char *)a, (*((struct Dict **)b))->name));
}

char *cfgfind(const char *name,struct Cfg *cfg, int offset)
{
    struct Dict **res;
    
    res=(struct Dict **)bsearch(name,
                                cfg->dict,
                                cfg->nelements,
                                sizeof(struct Dict *),
                                cfg_entry_match
    );
    
    if(!res)
        return NULL;
    
    if(offset>=(*res)->nvalues)
        return NULL;
    
    return (*res)->value[offset];
}

int writecfg(const char *name,struct Cfg *cfg)
{
    FILE *f;
    int  j;
    int i;

    if((f=fopen(name,"wb"))==NULL)
        return -1;
    
    if(cfg)
    {
        for(i=0;i<cfg->nelements;i++)
        {
            if(!cfg->dict[i]->name)
                continue;
            fprintf(f,"%s\t",cfg->dict[i]->name);
            for(j=0;j<cfg->dict[i]->nvalues;j++)
                if(cfg->dict[i]->value[j])
                    fprintf(f," %s",cfg->dict[i]->value[j]); //TODO: quote values with spaces.
            fprintf(f,"\n");
        }
    }
    fclose(f);
    return 0;
}

void freecfg(struct Cfg *cfg)
{
    int i,j;
    
    if(!cfg)
        return;
    
    for(i=0;i<cfg->nelements;i++)
    {
        if(cfg->dict[i]->value)
        {
            for(j=0;j<cfg->dict[i]->nvalues;j++)
                if(cfg->dict[i]->value[j])
                    free(cfg->dict[i]->value[j]);
            free(cfg->dict[i]->value);
        }
        
        if(cfg->dict[i]->name)
            free(cfg->dict[i]->name);
    }
    
    free(cfg->dict);
    free(cfg);
}

struct Cfg *readcfg(const char *name)
{
    struct Cfg *cfg;
    FILE       *f;
    char        tmp[MAXTOKENLEN];
    char       *s;
    int         c;
    
    enum 
    {
        START,
        NAME,
        VALUE,
        INQUOTE,
        WHITESPACE,
        COMMENT
    } state=START;
    
    if((f=fopen(name,"rb"))==NULL)
        return NULL;

    cfg=malloc(sizeof(struct Cfg));
    cfg->nelements=0;
    s=tmp;
    
    while((c=fgetc(f))!=EOF)
    {
        /* Order of 'case' statements is important here! */
        switch(state)
        {
        case START:
            if(c=='#')
            {
                state=COMMENT;
                break;
            }
            else
                if(!isspace(c))
                {
                    s=tmp;
                    state=NAME;
                } else
                {
                    break;
                }
            
        case NAME:
            if(isspace(c))
            {
                struct Dict *tmp1=malloc(sizeof(struct Dict));
                *s='\0';
                tmp1->nvalues = 0;
                tmp1->value   = NULL;
                tmp1->name    = strdup(tmp);
                
                cfg_add_entry(cfg, tmp1);
                
                state=WHITESPACE;
            }
            else
            {
                *s++=c;
                if(s==(tmp+sizeof(tmp)))
                {
                    /* internal buffer overflow */
                    freecfg(cfg);
                    fclose(f);
                    return NULL;
                }
            }
            break;

        case WHITESPACE:
            if(c=='\n')
            {
                state=START;
                break;
            }
            else
            {
                if(!isspace(c))
                {
                    s=tmp;
                    state=VALUE;
                } else
                {
                    break;
                }
            }
            
        case VALUE:
            if(c=='"')
                state=INQUOTE;
            else
                if(isspace(c))
                {
                    struct Dict *last=cfg->dict[cfg->nelements-1];
                    char **tmp1;
                    int  i;
                    
                    *s='\0';
                    tmp1=last->value;
                    last->value=malloc((last->nvalues+1)*sizeof(char *));
                    if(tmp1)
                    {
                        for(i=0;i<last->nvalues;i++)
                            last->value[i]=tmp1[i];
                        free(tmp1);
                    }
                    last->value[last->nvalues]=strdup(tmp);
                    last->nvalues++;
                    if(c=='\n')
                        state=START;
                    else
                        state=WHITESPACE;
                } else
                {
                    *s++=c;
                    if(s==(tmp+sizeof(tmp)))
                    {
                        /* internal buffer overflow */
                        freecfg(cfg);
                        fclose(f);
                        return NULL;
                    }
                }
            break;

        case INQUOTE:
            if(c=='"')
            {
                state=VALUE;
            }
            else
            {
                *s++=c;
                if(s==(tmp+sizeof(tmp)))
                {
                    /* internal buffer overflow */
                    freecfg(cfg);
                    fclose(f);
                    return NULL;
                }
            }
            break;

        case COMMENT:
            if(c=='\n')
                state=START;
            break;
        }
    }

    sortcfg(cfg);
    fclose(f);
    return cfg;
}

/**
 * Sorts cfg.
 * Should be called after each modification
 * before attempting to retrieve any data.
 */
void sortcfg (struct Cfg *cfg)
{
    qsort((void *) cfg->dict,
          cfg->nelements,
          sizeof(struct Dict *),
          cfg_entry_cmp);
    
}

/**
 * Adds new cfg entry to the end of the dictionary.
 * you need to call sortcfg() before it could be
 * really used.
 */
void cfg_add_entry (struct Cfg *cfg, struct Dict *d)
{
    if(cfg->nelements)
    {
        struct Dict **last=cfg->dict;
        cfg->dict=malloc(sizeof(struct Dict *)*(cfg->nelements+1));
        memcpy(cfg->dict,last,sizeof(struct Dict *)*cfg->nelements);
        cfg->dict[cfg->nelements]=d;
        cfg->nelements++;
        free(last);
    }
    else
    {
        cfg->dict      = malloc(sizeof(struct Dict *));
        cfg->dict[0]   = d;
        cfg->nelements = 1;
    }
}


/**
 * Adds entry with given name and list of values.
 * list should be terminated with NULL and contain
 * only const char pointers.
 */
void cfg_new_entry(struct Cfg *cfg, const char *name, ...)
{
    int n;
    va_list ap;
    struct Dict *tmp=malloc(sizeof(struct Dict));
    
    tmp->name    = strdup(name);
    
    va_start(ap,name);
    n=0;
    while(va_arg(ap, const char *)) n++;
    va_end(ap);

    tmp->nvalues = n;
    if(n)
    {
        int i;
        
        va_start(ap,name);
        tmp->value = malloc(n*sizeof(char *));
        for(i=0;i<n;i++)
            tmp->value[i] = strdup(va_arg(ap, const char *));
        va_end(ap);
    } else
    {
        tmp->value = NULL;
    }
    
    cfg_add_entry(cfg, tmp);
}

void  cfg_new_ulong_entry (struct Cfg *cfg, const char *name, unsigned long v)
{
    char tmp[80];
    sprintf(tmp,"%lu",v);
    cfg_new_entry(cfg, name, tmp, NULL);    
}

/**
 * add long extended to 'w' chars, with added trailing zeros.
 *
 * @param v - field value
 * @param w - field width
 */
void  cfg_new_fmt_ulong_entry (struct Cfg *cfg, const char *name, unsigned long v, int w)
{
    char tmp[80];
    sprintf(tmp,"%0*lu",w, v);
    cfg_new_entry(cfg, name, tmp, NULL);    
}

struct Cfg *newcfg ()
{
    struct Cfg *res=malloc(sizeof(struct Cfg));
    res->nelements  = 0;
    return res;
}
