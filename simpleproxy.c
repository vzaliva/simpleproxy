/*
 * $Id$
 * ---------------------------------------------------------------------
 *
 * Simple proxy daemon
 * ====================
 *
 * Authors:
 * --------
 * Vadim Zaliva    <lord@crocodile.org>
 * Vlad  Karpinsky <vlad@noir.crocodile.org>
 * Vadim Tymchenko <verylong@noir.crocodile.org>
 * Renzo Davoli <renzo@cs.unibo.it> (html probe & html basic authentication).
 *
 * Licence:
 * --------
 *
 * Copyright (C) 1999 Vadim Zaliva
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* #define DEBUG 1 */
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <sys/socket.h>
#ifndef _WIN32
# include <sys/un.h>
#endif
#include <sys/uio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdarg.h>
#if HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#if HAVE_STROPTS_H
# include <stropts.h>
#endif
#include <sys/stat.h>

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include <netdb.h>
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_TERMIO_H
# include <termio.h>
#endif
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netdb.h>

#include "cfg.h"

#ifndef nil
# define nil NULL
#endif

#ifndef SAME
# define SAME 0
#endif

#define MBUFSIZ 8192

#define SELECT_TIMOEOUT_SEC  5
#define SELECT_TIMOEOUT_MSEC 0

static char *SIMPLEPROXY_VERSION = "simpleproxy v3.5 by lord@crocodile.org,vlad@noir.crocodile.org,verylong@noir.crocodile.org,renzo@cs.unibo.it";
static char *SIMPLEPROXY_USAGE   = "simpleproxy -L <[host:]port> -R <host:port> [-d] [-v] [-V] [-7] [-i] [-u] [-p PID file] [-P <POP3 accounts list file>] [-f cfgfile] [-t tracefile] [-D delay in sec.] [-S <HTTPS proxy host:port> [-a <HTTPS Auth user>:<HTTPS Auth password>] ] [-A  <HTTP Auth user>:<HTTP Auth password>]";
static char *PROXY_HEADER_FMT = "\r\nProxy-Authorization: Basic %s";
static char *PROXY_HEADER = "\r\nProxy-Authorization: Basic ";
static char AUTHMSG[]=
"HTTP/1.1 407 Proxy Authorization Required\r\n"
"Proxy-Authenticate: Basic realm=\"";
static char AUTHMSG2[]= "\"\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<HTML><HEAD>\r\n"
"<TITLE>407 Proxy Authorization Required</TITLE>\r\n"
"</HEAD><BODY>\r\n"
"<H1>Proxy Authorization Required</H1>\r\n"
"Login and Password required\r\n"
"<hr>\r\nSimpleProxy\r\n"
"</BODY></HTML>\r\n";

struct lst_record
{
    char *s;
    struct lst_record *next;
};

static void daemon_start(void);
static int  writen(int fd, char *ptr, int nbytes);
static void pass_all(int fd, int client);
static int  pass_out( int in, int out);
static int  pass_in( int in, int out, int isHtmlProbe,char *authHash);
static int  get_hostaddr(const char *name);
static int  readln(int fd, char *buf, int siz);
static void firstword(char *str);
static struct lst_record * load_pop3_list(const char *popfile);
static int  check_pop3_list(struct lst_record *lst, char *acc);
static int  pop3_login(int remotefd,int newsockfd);
static int  read_pop3_cmd(int s, char *buff, int max_buf, int strip);
static void child_dead( int stat );
static void write_pid( char* filename );
static int  process_remote(const char *rhost, int rportn,const char *client_name);
static int  open_remote(const char *rhost, int rportn,const char *client_name);
static void logopen(void);
static void logclose(void);
static void logmsg(int, char *format, ...);
static void ctrlc(int);
static int  https_connect(int remoteFd, const char *remoteHost, int remotePort);
static int  str2bool(char *s);
static void parse_host_port(const char *src, char **h_ptr, int *p_ptr);
static void replace_string(char **dst, const char*src);
static void fatal();
static char *base64_encode(char *plaintext);
static void trace(int fd, char *buf, int siz);

static int   isVerbose          = 0;
static int   isDaemon           = 0;
static int   isStripping        = 0;
static int   isStartedFromInetd = 0;
static int   isUsingHTTPSAuth   = 0;
static int   isHtmlProbe        = 0;
static long  Delay              = 0;

static char *HTTPSProxyHost     = nil;
static int   HTTPSProxyPort     = -1;
static char *HTTPSBasicAuthString = nil;
static char *HTTPAuthHash = nil;
static char *Tracefile          = nil;

static int  SockFD    = -1,
    SrcSockFD = -1,
    DstSockFD = -1;

struct lst_record *POPList = nil;

int main(int ac, char **av)
{
    socklen_t    clien;
    struct sockaddr_in cli_addr, serv_addr;
    int    lportn = -1, rportn = -1;
    char  *lhost = nil, *rhost = nil;
    struct hostent *hp;
    char  *client_name;
    extern char *optarg;
    int    c;
    int    errflg = 0;
    char  *cfgfile = nil;
    char  *popfile = nil;
    static struct Cfg *cfg = nil;
    char  *pidfile = nil;
    int    rsp = 1;
    char  *https_auth = nil;
    char  *http_auth = nil;
    char  *HTTPSAuthHash = nil;
    int    len;
    char   hbuf[NI_MAXHOST];

    /* Check for the arguments, and overwrite values from cfg file */
    while((c = getopt(ac, av, "iVv7dhuL:R:H:f:p:P:D:S:s:a:A:t:")) != -1)
        switch (c)
        {
        case 'v':
            isVerbose++;
            break;
        case 'i':
            isStartedFromInetd++;
            break;
        case 'd':
            isDaemon++;
            break;
        case 'u':
            isHtmlProbe++;
            break;
        case 'p':
            replace_string(&pidfile, optarg);
            break;
        case 'f':
            replace_string(&cfgfile, optarg);
            if(cfgfile)
            {
                if((cfg=readcfg(cfgfile))==nil)
                {
                    logmsg(LOG_ERR,"Error reading cfg file.");
                    return 1;
                }
                else
                {
                    char *tmp;
                    /* let's process cfg file. Will cnage options only if they were not set already*/
                    if (!isVerbose)
                        isVerbose = str2bool(cfgfind("Verbose", cfg, 0));
                    if (!isStartedFromInetd)
                        isStartedFromInetd = str2bool(cfgfind("StartedFromInetd",cfg, 0));
                    if (!isDaemon)
                        isDaemon = str2bool(cfgfind("Daemon", cfg, 0));
                    if (!isStripping)
                        isStripping = str2bool(cfgfind("Strip8bit", cfg, 0));
                    if (!isHtmlProbe)
                        isHtmlProbe = str2bool(cfgfind("HtmlProbe", cfg, 0));

                    tmp = cfgfind("LocalPort", cfg, 0);
                    if (tmp && lportn == -1)
                        parse_host_port(tmp, nil, &lportn);
                    tmp = cfgfind("RemotePort", cfg, 0);
                    if (tmp && rportn == -1)
                        parse_host_port(tmp, nil, &rportn);
                    tmp = cfgfind("HTTPSProxyPort",cfg, 0);
                    if (tmp && HTTPSProxyPort == -1)
                        parse_host_port(tmp, nil, &HTTPSProxyPort);

                    tmp = cfgfind("PIDFile", cfg, 0);
                    if(tmp && !pidfile)
                        replace_string(&pidfile, tmp);
                    tmp = cfgfind("POP3File", cfg, 0);
                    if(tmp && !popfile)
                        replace_string(&popfile, tmp);
                    tmp = cfgfind("LocalHost", cfg, 0);
                    if(tmp && !lhost)
                        parse_host_port(tmp, &lhost, &lportn);
                    tmp = cfgfind("RemoteHost", cfg, 0);
                    if(tmp && !rhost)
                        parse_host_port(tmp, &rhost, &rportn);
                    tmp = cfgfind("HTTPSProxyHost",cfg, 0);
                    if(tmp && !HTTPSProxyHost)
                        parse_host_port(tmp, &HTTPSProxyHost, &HTTPSProxyPort);
                    tmp = cfgfind("TraceFile", cfg, 0);
                    if(tmp && !Tracefile)
                        replace_string(&Tracefile, tmp);
                    tmp = cfgfind("https_auth", cfg, 0);
                    if(tmp && !https_auth) {
                        isUsingHTTPSAuth = 1;
                        replace_string(&https_auth, tmp);
                    }
                    tmp = cfgfind("http_auth", cfg, 0);
                    if(tmp && !http_auth)
                        replace_string(&http_auth, tmp);
                    freecfg(cfg);
                }
            }
            break;
        case 'L':
            parse_host_port(optarg, &lhost, &lportn);
            break;
        case 'P':
            replace_string(&popfile, optarg);
            break;
        case 'R':
            parse_host_port(optarg, &rhost, &rportn);
            break;
        case 'H':
            replace_string(&rhost, optarg);
            break;
        case 'D':
            Delay = atol(optarg);
            break;
        case '7':
            isStripping = 1;
            break;
        case 'S':
            parse_host_port(optarg, &HTTPSProxyHost, &HTTPSProxyPort);
            break;
        case 's':
            parse_host_port(optarg, nil, &HTTPSProxyPort);
            break;
        case 'V':
            fprintf(stderr, "%s\n", SIMPLEPROXY_VERSION);
            exit(0);
        case 'h':
            errflg++; // to make it print 'Usage:...'
            break;
        case 'a':
            if((HTTPSProxyHost == nil) && (HTTPSProxyPort == -1))
                fprintf(stderr, "Warning! Proxy authorization (-a) meaningless without HTTPS parameters (-S)\n");
            isUsingHTTPSAuth = 1;
            replace_string(&https_auth,optarg);
            break;
        case 'A':
            replace_string(&http_auth,optarg);
            break;
        case 't':
            replace_string(&Tracefile, optarg);
            break;
        default:
            errflg++;
        }

    /* let us check options compatibility and completness*/

    if(isUsingHTTPSAuth)
    {
        HTTPSAuthHash        = base64_encode(https_auth);
        HTTPSBasicAuthString = malloc(strlen(HTTPSAuthHash) + strlen(PROXY_HEADER_FMT));
        sprintf(HTTPSBasicAuthString,PROXY_HEADER_FMT,HTTPSAuthHash);
        free(HTTPSAuthHash);
    } else
    {
        HTTPSBasicAuthString = "";
    }

    if(http_auth)
        HTTPAuthHash = base64_encode(http_auth);

    if (isStartedFromInetd && lportn > 0)
        errflg++;

    if (!rhost                               ||
        rportn <= 0                          ||
        (lportn <= 0 && !isStartedFromInetd) ||
        (HTTPSProxyHost && HTTPSProxyPort <=0))
        errflg++;

    /* Do some options post-processing */

    if(isStartedFromInetd)
        isDaemon++;  /* implies */

    if(errflg)
    {
        (void)fprintf(stderr, "%s\n", SIMPLEPROXY_VERSION);
        (void)fprintf(stderr, "Usage:\n\t%s\n", SIMPLEPROXY_USAGE);
        exit(1);
    }

    logopen();

    if(signal(SIGINT,ctrlc)==SIG_ERR)
        logmsg(LOG_ERR,"Error installing interrupt handler.");

    if(lportn <= 1024 && geteuid()!=0 && !isStartedFromInetd)
    {
        if(!isVerbose)
        {
            logopen();
            isVerbose++;
        }
        logmsg(LOG_ERR,"You must be root to run SIMPLEPROXY on reserved port");
        fatal();
    }

    if (popfile)
        POPList = load_pop3_list(popfile);

    if (!isStartedFromInetd)
    {
        /* Let's become a daemon */
        if(isDaemon)
            daemon_start();

        if(pidfile)
            write_pid(pidfile);

        if((SockFD = socket(AF_INET,SOCK_STREAM,0)) < 0)
        {
            logmsg(LOG_ERR,"Error creating socket.");
            fatal();
        }

        memset((void *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = ((lhost && *lhost)? get_hostaddr(lhost): htonl(INADDR_ANY));
        serv_addr.sin_port = htons(lportn);

        if (setsockopt(SockFD, SOL_SOCKET, SO_REUSEADDR, (void*)&rsp, sizeof(rsp)))
            logmsg(LOG_ERR,"Error setting socket options");

        if (bind(SockFD, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            logmsg(LOG_ERR,"Error binding socket.");
            fatal();
        }

        logmsg(LOG_INFO,"Waiting for connections.");

        if (listen(SockFD,5) < 0)
        {
            logmsg(LOG_ERR,"Error listening socket: %s", strerror(errno));
            fatal();
        }

        while (1)
        {
            clien = sizeof(cli_addr);

            SrcSockFD = accept(SockFD,(struct sockaddr *)&cli_addr, &clien);

            if(SrcSockFD < 0)
            {
                if (errno == EINTR || errno == ECHILD) /* Interrupt after SIGCHLD */
                    continue;
                logmsg(LOG_ERR, "accept error - %s", strerror(errno));
                fatal();
            }

            signal(SIGCHLD, child_dead);

            switch (fork())
            {
            case -1: /* fork error */
                logmsg(LOG_ERR,"fork error - %s", strerror(errno));
                break;

            case 0: /* Child */
                if (getnameinfo((const struct sockaddr *) &cli_addr, len,
                                hbuf, sizeof(hbuf), NULL, 0, 0) == 0)
                    client_name = strdup(hbuf);
                else
                    client_name = inet_ntoa(cli_addr.sin_addr);

                /*
                 * I don't know is that a bug, but on Irix 6.2 parent
                 * process will not be able to accept any new connection
                 * if SockFD is closed here.                  Vlad
                 */

                /* (void)shutdown(SockFD,2); */
                /* (void)close(SockFD);      */

                /* Process connection */

                logmsg(LOG_NOTICE,
                       "Connect from %s (%s:%d->%s:%d)",
                       client_name,
                       ((lhost && *lhost)? lhost: "ANY"),     lportn,
                       (rhost && *rhost)? rhost: "localhost", rportn);

                if (process_remote(rhost, rportn, client_name))
                    fatal();

                logmsg(LOG_NOTICE,
                       "Connect from %s (%s:%d->%s:%d) closed",
                       client_name,
                       ((lhost && *lhost)? lhost: "ANY"), lportn,
                       (rhost && *rhost)? rhost: "localhost", rportn);

                shutdown(SrcSockFD, 2);
                close(SrcSockFD);
                SrcSockFD = -1;
                closelog();
                return 0; // Exit
            default:
                /* Parent */
                close(SrcSockFD);
                SrcSockFD = -1;
            }
        }
    }
    else
    {
        /* Started from inetd */
        SrcSockFD = 0; // stdin

        logmsg(LOG_NOTICE,
               "Connect (inetd->%s:%d)",
               (rhost && *rhost)? rhost: "localhost", rportn);

        process_remote(rhost, rportn, "inetd");
        logmsg(LOG_NOTICE,
               "Connect (inetd->%s:%d) closed",
               (rhost && *rhost)? rhost: "localhost", rportn);
    }
    return 0;
}

/*
 * Write "n" bytes to a descriptor.
 * Use in place of write() when fd is a stream socket.
 */
static int writen(int fd, char *ptr, int nbytes)
{
    int nleft, nwritten;

    nleft = nbytes;
    while (nleft > 0)
    {
        nwritten = write(fd, ptr, nleft);
        if(nwritten <= 0)
            return(nwritten);       /* error */

        nleft -= nwritten;
        ptr   += nwritten;
    }
    return(nbytes - nleft);
}

/*
 * Detach a daemon process from login session context.
 */
static void daemon_start(void)
{
    /* Maybe I should do 2 forks here? */

    if(fork())
        exit(0);
    if(chdir("/")) {} /* supressing warn_unused_result */
    umask(0);
    (void) close(0);
    (void) close(1);
    (void) close(2);
    (void) open("/", O_RDONLY);
    (void) dup2(0, 1);
    (void) dup2(0, 2);
    setsid();
}


void pass_all( int fd, int client )
{
    fd_set         in;
    struct timeval tv;
    int            nsock, retval;

    nsock = ((fd > client)? fd: client) + 1;

    while(1)
    {
        FD_ZERO(&in);
        FD_SET(fd, &in);
        FD_SET(client, &in);

        tv.tv_sec  = SELECT_TIMOEOUT_SEC;
        tv.tv_usec = SELECT_TIMOEOUT_MSEC;

        retval = select(nsock, &in, nil, nil, &tv);

        switch (retval)
        {
        case  0 :
            /* Nothing to receive */
            break;
        case -1:
            /* Error occured */
            logmsg(LOG_ERR, "i/o error - %s", strerror(errno));
            return;
        default:
            if(FD_ISSET( fd, &in))
                retval = pass_out(fd, client);
            else if(FD_ISSET( client, &in))
                retval = pass_in(client, fd, isHtmlProbe, HTTPAuthHash);
            else
                retval = -1;
            if( retval < 0)
                return;
            if(Delay > 0)
                sleep(Delay);
        }
    }
}

static int get_hostaddr(const char *name)
{
    struct hostent *he;
    int             res = -1;
    int             a1,a2,a3,a4;

    if (sscanf(name,"%d.%d.%d.%d",&a1,&a2,&a3,&a4) == 4)
        res = inet_addr(name);
    else
    {
        he = gethostbyname(name);
        if (he)
            memcpy(&res , he->h_addr , he->h_length);
    }
    return res;

}

/* credit: some code for html probe has been taken from dsniff (renzo davoli)*/

static int strrindex (const char *s, int c, int pos)
{
    if (pos >= 0) {
        pos--;
        while (pos >= 0  && s[pos] != c)
            pos--;
    }
    return pos;
}

static int
is_display_uri(char *uri)
{
    static char *good_prefixes[] = { NULL };
    static char *good_suffixes[] = { ".html", ".htm", "/", ".shtml",
                                     ".cgi", ".asp", ".php3", ".txt",".pdf",
                                     ".xml", ".asc", NULL };
#ifdef INSEARCH
    static char *good_infixes[] = { ".cgi", ".asp", ".php3", NULL };
#endif
    int len, slen, pos;
    char **pp, *p;

    /* printf("is_display_uri %s\n",uri);*/

    /* Get URI length, without QUERY_INFO */
    if ((p = strchr(uri, '?')) != NULL) {
        len = p - uri;
    }
    /* Get URI length, without TAG */
    else if ((p = strchr(uri, '#')) != NULL) {
        len = p - uri;
    }
    else {
        /* no '?', no '#', maybe dir */
        len = strlen(uri);
        pos=strrindex(uri,'/',len);
        if (pos >= 0) {
            if (strchr(&uri[pos+1],'.') == NULL &&
                strchr(&uri[pos+1],'=') == NULL &&
                strchr(&uri[pos+1],'&') == NULL)
                return 1;
        }
    }

    for (pp = good_suffixes; *pp != NULL; pp++) {
        if (len < (slen = strlen(*pp))) continue;
        if (strncasecmp(&uri[len - slen], *pp, slen) == 0)
            return (1);
    }
    for (pp = good_prefixes; *pp != NULL; pp++) {
        if (len < (slen = strlen(*pp))) continue;
        if (strncasecmp(uri, *pp, slen) == 0)
            return (1);
    }
#ifdef INSEARCH
    for (pp = good_infixes; *pp != NULL; pp++) {
        for (pos = len; pos > (slen = strlen(*pp)); pos = strrindex(uri,'/',pos)) {
            if (strncasecmp(&uri[pos - slen], *pp, slen) == 0)
                return (1);
        }
    }
#endif
    return (0);
}

static char *strxdup(const char *s, size_t n)
{
    char *result=malloc(n+1);
    if (result != NULL) {
        memcpy(result,s,n);
        result[n]=0;
    }
    return result;
}

static int
process_http_request(char *data, int len)
{
    char *uri, *enduri;

    data[len]=0;
    //printf("process_http_request(%d)\n%s\nEND\n",getpid(),data);
    if (strncmp(data, "GET ", 4)==0) {
        uri = data+4;
        if ((enduri=strchr(uri,' ')) != NULL) {
            uri=strxdup(uri,(size_t)(enduri-uri));

            //printf("uri %s\n",uri);

            if (is_display_uri(uri)) {
                printf("%s\n",uri);
                fflush(stdout);
            }
            free(uri);
        }
    }
    return 0;
}

static int pass_out( int in, int out)
{
    int nread;
    char buff[MBUFSIZ];

    if ((nread = readln(in, buff,MBUFSIZ)) <= 0)
        return -1;
    else
    {
        if (isStripping)
        {
            char *bufp;
            for (bufp = buff+nread-1; bufp >= buff; bufp--)
                *bufp = *bufp&0177;
        }

        if(writen(out, buff, nread) != nread)
        {
            logmsg(LOG_ERR,"write error");
            return -1;
        }
    }
    return 0;
}

static int auth_check (char *buf, int len, char *http_authhash)
{
    char *match;
    if ((match=strstr(buf,PROXY_HEADER)) != NULL) {
        int authlen=strlen(PROXY_HEADER)+strlen(http_authhash);
        if (((match - buf)-authlen) <= len) {
            if (strncmp(match+strlen(PROXY_HEADER),http_authhash,strlen(http_authhash))==0 &&
                (*(match + authlen) == '\r' || *(match + authlen) == '\n')) {
                memmove(match,match+authlen,(match-buf)-authlen);
                return(len-authlen);
            } else
                return 0;
        }
        else
            return 0;
    } else
        return 0;
}

static int pass_in( int in, int out , int htmlProbe, char *http_authhash)
{
    int nread;
    static char *buff=NULL;
    static int size=0;
    static int len=0;
    /* printf("HASH %s|=== %d\n",http_authhash,getpid()); */

    if ((size - len) == 0) {
        if (size==0) size=MBUFSIZ;
        else size *= 2;
        buff = realloc(buff,size+1);
        if (!buff)
            return -1;
    }

    if ((nread = readln(in, buff+len, size-len)) <= 0)
        return -1;
    {
        char *pos;
        len+=nread;
        buff[len]=0;
        /* printf("R %d %d ==%s==\n",nread,len,buff); */

        if (htmlProbe || http_authhash != NULL) {
            /* http basic parsing (allowing persistent connections and pipelining) */

            while ((pos=strstr(buff,"\r\n\r\n")) != NULL) {
                int nout;
                nout=nread=(pos-buff)+4;
                /* printf("C %d %d ==%s==\n",nread,len,buff); */
                if (isStripping)
                {
                    char *bufp;
                    for (bufp = buff+nread-1; bufp >= buff; bufp--)
                        *bufp = *bufp&0177;
                }

                /* authentication management */
                if (http_authhash != NULL && (nout = auth_check(buff,nread,http_authhash)) == 0) {
                    writen(in,AUTHMSG,sizeof(AUTHMSG));
                    writen(in,"SimpleProxy",11);
                    writen(in,AUTHMSG2,sizeof(AUTHMSG2));
                    return -1;
                } else {
                    if(writen(out, buff, nout) != nout)
                    {
                        logmsg(LOG_ERR,"write error");
                        return -1;
                    }

                    /* probe: display on stdout significant URLs */
                    if (htmlProbe)
                        process_http_request(buff, nout);
                }

                len -= nread;
                if (len>0)
                    memmove(buff,buff+nread,len);
                else
                    *buff=0;
            }
        } else {
            if (isStripping)
            {
                char *bufp;
                for (bufp = buff+nread-1; bufp >= buff; bufp--)
                    *bufp = *bufp&0177;
            }
            if(writen(out, buff, len) != len)
            {
                logmsg(LOG_ERR,"write error");
                return -1;
            }
            len -= nread;
            *buff=0;
        }
    }
    return 0;
}

void child_dead( int stat )
{
    while(waitpid( -1, nil, WNOHANG ) > 0);
    signal( SIGCHLD, child_dead );
}

void parse_host_port(const char *src, char ** h_ptr, int *p_ptr)
{
    if(src)
    {
        struct servent *se;
        /* Look for ':' separator */
        const char *tmp = strrchr(src, ':');

        if (tmp)
        {
            if (h_ptr)
            {
                replace_string(h_ptr, src);

                /* This looks like host:port syntax */

                *((*h_ptr) + (tmp - src)) = '\0';
            }
            tmp++;
        }
        else
            tmp = src; /* to compensate future ++; */


        *p_ptr = (isdigit(*tmp))?
        atoi(tmp):
        (((se = getservbyname(tmp, "tcp")) == nil)?
         -1:
         ntohs(se->s_port));
    }
}

void write_pid( char* filename )
{
    FILE *f;

    if((f=fopen(filename,"w"))==nil)
    {
        logmsg(LOG_WARNING,"Can't open file '%s' to write PID",filename);
        return;
    }

    fprintf( f,"%d",getpid());
    fclose( f );
    return;
}

/**
 * Load list of allowed POP3 accounts from external file
 * One per line
 */
static struct lst_record *load_pop3_list(const char *popfile)
{
    FILE *f;
    char str[2048];
    struct lst_record *first = nil;
    struct lst_record *last  = nil;

    if((f=fopen(popfile,"r"))==nil)
    {
        logmsg(LOG_ERR,"Can't open POP3 file: %s",popfile);
        return nil;
    }

    while((str==fgets(str,2040,f)))
    {
        if(*str=='#') continue; /* comment */

        firstword(str);
        if(*str=='\0') continue;
        logmsg(LOG_INFO,"Adding '%s' to POP3 users list",str);

        if(first==nil)
        {
            first=(struct lst_record *)malloc(sizeof(struct lst_record));
            last=first;
        } else {
            last->next=(struct lst_record *)malloc(sizeof(struct lst_record));
            last=last->next;
        }
        last->s=strdup(str);
        last->next=nil;
    }

    fclose(f);
    return first;
}

/**
 * Check if given account is OK to proxy
 */
static int check_pop3_list(struct lst_record *lst, char *acc)
{
    while (lst)
    {
        if(strcmp(lst->s, acc) == 0)
            return 1; /* found */
        else
            lst = lst->next;
    }
    return 0;
}

static void firstword(char *s)
{
    s=strpbrk(s,"\n\t\r ");
    if(s)
        *s='\0';
}

static int  readln(int fd, char *buf, int siz)
{
    int  nread;

    nread = read(fd, buf, siz);
    if(nread <= 0)
    {
        if(nread < 0)
            logmsg(LOG_ERR,"read error");
        return -1;
    } else
    {
        if (Tracefile)
        {
            // do tracing;
            trace(fd, buf, nread);
        }
        return nread;
    }
}


/**
 * . reads single POP3 command from socket.
 * . strips \r and \n at the end
 * . returns number of chars left or -1 in case of read error.
 */
static int read_pop3_cmd(int s, char *buff, int max_buf, int strip)
{
    int n;

    if((n=readln(s,buff,max_buf))<=0) return -1; /* read error */
    do {
        buff[n--]='\0';
    } while((buff[n]=='\r' || buff[n]=='\n') && n>=0 && strip);

    return n;
}

/*
 * Pass USER command to remote end only if user is in the list
 *
 * See RFC1725 for details.
 */
static int pop3_login(int server,int user)
{
    static char errmsg0[]={"-ERR Not allowed by proxy\r\n"    };
    static char errmsg1[]={"-ERR Can't get your user name\r\n"};
    static char errmsg2[]={"-ERR USER or QUIT command expected\r\n"   };
    static char errmsg3[]={"-ERR PASS or QUIT command expected\r\n"   };

    char buff[MBUFSIZ];
    char *s;

    /* read +OK from server */
    if(readln(server,buff,MBUFSIZ)<=0) return 1; /* read error */
    if(strncmp(buff,"+OK",3)        !=0) return 1; /* server is not OK */

    /* Send client our OK */
    writen(user, "+OK ",4);
    writen(user, SIMPLEPROXY_VERSION, strlen(SIMPLEPROXY_VERSION));
    writen(user, "\r\n",2);

    while(1)
    {
        /* read cmd from client */
        if(read_pop3_cmd(user, buff, MBUFSIZ, 1) <= 0)
            return 1;

        if(strncmp(buff,"QUIT ",4) ==SAME)
            return 1;

        if(strncmp(buff,"USER ",5) !=SAME)
        {
            /* first command is not USER */
            writen(user,errmsg2,strlen(errmsg2)); /* Send error to client */
            continue;
        }

        /* get user name */
        s=strdup(buff+5);
        firstword(s);
        if(*s == '\0')
        {
            /* invalid user name */
            free(s);
            writen(user,errmsg1,strlen(errmsg1)); /* Send error to client */
            continue;
        }

        /* Search user in access list */
        if(check_pop3_list(POPList, s) == 0)
        {
            /* user not found */
            free(s);
            writen(user,errmsg0,strlen(errmsg0)); /* Send error to client */
            continue;
        }

        /* forward USER command to server */
        writen(server,buff,strlen(buff));
        writen(server,"\r\n",2);

        /* Get server response to USER */
        if(read_pop3_cmd(server, buff, MBUFSIZ,0)<=0) return 1; /* read error */
        /* forward  server response to client */
        writen(user,buff,strlen(buff));

        if(strncmp(buff,"+OK",3)  !=SAME)
            continue; /* USER is not OK */

        while(1)
        {
            if(read_pop3_cmd(user, buff, MBUFSIZ, 0)<=0)
                return 1;

            if(strncmp(buff,"QUIT ",4) ==SAME)
                return 1;

            if(strncmp(buff,"PASS ",5) == SAME)
                break;

            /* second command not PASS */
            writen(user,errmsg3,strlen(errmsg3)); /* Send error to client */
            continue;
        }

        /* forward PASS command to server */
        writen(server,buff,strlen(buff));

        /* read pass response */
        if(read_pop3_cmd(server, buff, MBUFSIZ, 0)<=0) return 1; /* read error */

        writen(user,buff,strlen(buff)); /* forward server response to client */

        if(strncmp(buff,"+OK",3) == SAME)
            return 0; /* ok */
    }
    /* NOTREACHED */
}

int process_remote(const char *dest_host, int dest_port, const char *client_name)
{
    DstSockFD = open_remote(dest_host, dest_port, client_name);

    if (DstSockFD == -1)
        return -1;

    if (POPList && /* Doing POP3 proxy */ pop3_login(DstSockFD, SrcSockFD))
    {
        logmsg(LOG_ERR,"POP3 login failed for %s.", client_name);
        return -1;
    }

    pass_all(DstSockFD, SrcSockFD);

    shutdown(DstSockFD, 2);
    close(DstSockFD);
    DstSockFD = -1;
    return 0;
}

int open_remote(const char *rhost, int rportn, const char *src_name)
{
    const char        *dest_host;
    int                dest_port;
    struct sockaddr_in remote_addr;
    int                DstSockFD;


    if (HTTPSProxyHost)
    {
        dest_host = HTTPSProxyHost;
        dest_port = HTTPSProxyPort;
    }
    else
    {
        dest_host = rhost;
        dest_port = rportn;
    }

    if (!(dest_host && *dest_host))
        dest_host = "127.0.0.1";

    if ((DstSockFD = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        logmsg(LOG_ERR,"Can't create socket - %s ", strerror(errno));
        return -1;
    }

    remote_addr.sin_family      = AF_INET;
    remote_addr.sin_port        = htons(dest_port);
    remote_addr.sin_addr.s_addr = get_hostaddr(dest_host);

    if (remote_addr.sin_addr.s_addr == -1)
    {
        logmsg(LOG_ERR,"Unknown host %s", dest_host);
        return -1;
    }

    if (connect(DstSockFD, (struct sockaddr *) &remote_addr, sizeof(remote_addr)))
    {
        logmsg(LOG_ERR,"connect error to %s:%d - %s", dest_host, dest_port, strerror(errno));
        return -1;
    }

    if (HTTPSProxyHost && https_connect(DstSockFD, rhost, rportn))
        return -1;

    return DstSockFD;
}

static int https_connect(int DstSockFD, const char *remoteHost, int remotePort)
{
    char buff[MBUFSIZ];
    char *s;
    long  n;

    /* prepare command and connect to remote side */
    sprintf(buff, "CONNECT %s:%i HTTP/1.0\nUser-agent: %s%s\r\n\r\n",
            remoteHost, remotePort, SIMPLEPROXY_VERSION,HTTPSBasicAuthString);
    n = strlen(buff);

    if (writen(DstSockFD, buff, n) != n)
    {
        logmsg(LOG_ERR, "write error - %s", strerror(errno));
        return -1; /* write error */
    }

    /* reading response from the server */
    if (readln(DstSockFD,buff,MBUFSIZ) <= 0)
    {
        logmsg(LOG_ERR,"read error - %s", strerror(errno));
        return -1; /* read error */
    }

    /* Format of HTTPS proxy responce must be: <Protocol> <code> <message> */
    if(!(s = strchr(buff, ' ')))
        return -1;
    if((n = strtol(s, &s, 10)) != 200)
    {
        logmsg(LOG_ERR,"error in connect through HTTPS proxy. Proxy responded:\n %s", buff);
        return -1;
    }
    return 0; /* ok */
}

static void logopen(void)
{
    if(isVerbose & isDaemon)
    {
#if HAVE_OPENLOG
        openlog("simpleproxy", LOG_PID| LOG_CONS|LOG_NOWAIT, LOG_USER);
#else
        log(LOG_WARNING,"Compiled without syslog. Syslog can't be used.");
#endif
    }

}

static void logclose(void)
{
    if(isVerbose && isDaemon)
    {
#if HAVE_CLOSELOG
        closelog();
#endif
    }
}

/**
 * This function should be used as central logging facility.
 * 'type' argument should be one of following:
 *
 *  LOG_EMERG   system is unusable
 *  LOG_ALERT   action must be taken immediately
 *  LOG_CRIT    critical conditions
 *  LOG_ERR error conditions
 *  LOG_WARNING warning conditions
 *  LOG_NOTICE  normal but significant condition
 *  LOG_INFO    informational
 *  LOG_DEBUG   debug-level messages
 */
static void logmsg(int type, char *format, ...)
{
#ifndef DEBUG
    if(type==LOG_DEBUG)
        return;
#endif

    if(isVerbose)
    {
        va_list ap;
        va_start(ap, format);

        if(isDaemon)
        {
            char buffer[MBUFSIZ];

#if HAVE_VSNPRINTF
            (void)vsnprintf(buffer, MBUFSIZ, format, ap);
#else
# if HAVE_VSPRINTF
#  ifndef SGI
#   warning "Using VSPRINTF. Buffer overflow could happen!"
#  endif /* SGI */
            (void)vsprintf(buffer, format, ap);
# else
#  error "Your standard libabry have neither vsnprintf nor vsprintf defined. One of them is reqired!"
# endif
#endif
#if HAVE_SYSLOG
            syslog(type, "%s", buffer);
#endif
        } else
        {
            (void) fprintf(stderr, "simpleproxy[%d]:", (int)getpid());
            (void) vfprintf(stderr, format, ap);
            (void) fprintf(stderr, "\n");
        }
        va_end(ap);
    }
}

static void ctrlc(int s)
{
    logmsg(LOG_INFO,"Interrupted... Shutting down connections");

    if(SockFD    !=-1)
    {
/*  (void)shutdown(SockFD,2); */
        (void)close(SockFD   );
    }
    if(SrcSockFD !=-1)
    {
/*  (void)shutdown(SrcSockFD,2); */
        close(SrcSockFD);
    }
    if(DstSockFD !=-1)
    {
/*  (void)shutdown(DstSockFD,2); */
        close(DstSockFD );
    }

    /* system V style. */
/*    if(signal(SIGINT,ctrlc)==SIG_ERR)
      logmsg(LOG_INFO,"Error installing interrupt handler."); */
    exit(1);
}

/**
 * Returns 1 if string could be interpreted as boolean TRUE in cfg.
 * otherwise returns 0.
 */
int str2bool(char *s)
{
    if(s==nil)
        return 0;
    else
        return !(strcasecmp(s,"yes")  &&
                 strcasecmp(s,"true") &&
                 strcasecmp(s,"ok")  &&
                 strcasecmp(s,"oui") &&
                 strcasecmp(s,"1")
        );
}

void replace_string(char **dst, const char *src)
{
    if(dst)
    {
        if(*dst)
            free(*dst);
        *dst = (src)? strdup(src): nil;
    }
}

void fatal()
{
    if (SockFD != -1)
        close(SockFD);
    if (SrcSockFD != -1)
        close(SrcSockFD);
    if (DstSockFD != -1)
        close(DstSockFD);
    logclose();
    exit(1);
}

static char *base64_encode(char *plaintext)
{
    int i;
    unsigned char dtable[64];
    char *cryptext = nil;
    char *ogroup;

    /* Fill dtable with base 64 character encodings.  */

    for (i = 0; i < 26; i++) {
        dtable[i] = 'A' + i;
        dtable[26 + i] = 'a' + i;
    }
    for (i = 0; i < 10; i++) {
        dtable[52 + i] = '0' + i;
    }
    dtable[62] = '+';
    dtable[63] = '/';

    cryptext = malloc(strlen(plaintext)*2);
    ogroup=cryptext;

    while (*plaintext != 0)
    {
        unsigned char igroup[3];
        int n;

        igroup[0] = igroup[1] = igroup[2] = 0;

        for (n = 0; n < 3; n++)
        {
            if(*plaintext != 0)
                igroup[n]=*plaintext++;
            else
                break;
        }

        if (n > 0)
        {
            ogroup[0] = dtable[igroup[0] >> 2];
            ogroup[1] = dtable[((igroup[0] & 3) << 4) | (igroup[1] >> 4)];
            ogroup[2] = dtable[((igroup[1] & 0xF) << 2) | (igroup[2] >> 6)];
            ogroup[3] = dtable[igroup[2] & 0x3F];

            /* Replace characters in output with "=" pad
               characters if fewer than three characters were
               available in the input stream. */

            if (n < 3) {
                ogroup[3] = '=';
                if (n < 2) {
                    ogroup[2] = '=';
                }
            }

            ogroup += 4;

        }
    }
    *ogroup = '\0';
    return cryptext;
}

static void trace(int fd, char *buf, int siz)
{
    char peer_name[NI_MAXHOST+16]; /* 16 bytes from column and port number */
    char trace_header[256];
    int trace_header_len;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    struct hostent *peer_host;
    ssize_t unused_bytes_written;
    int tfd = open(Tracefile, O_CREAT | O_WRONLY| O_APPEND, S_IRUSR | S_IWUSR |  S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if(tfd < 0)
    {
        logmsg(LOG_ERR,"Tracing is disabled, can't create/open trace file - %s", strerror(errno));
        free(Tracefile);
        Tracefile = nil;
    }
    else
    {
        if(getpeername(fd, (struct sockaddr *)&peer_addr, &peer_addr_len) == 0)
        {
            char hbuf[NI_MAXHOST];
            char *client_host_name;

            if(getnameinfo((const struct sockaddr *) &peer_addr, peer_addr_len,
                           hbuf, sizeof(hbuf), NULL, 0, 0) == 0)
                client_host_name = hbuf;
            else
                client_host_name = inet_ntoa(peer_addr.sin_addr);

            snprintf(peer_name, sizeof(peer_name)  - 1, "%s:%i",
                     client_host_name, ntohs(peer_addr.sin_port));
        }
        else
            strcpy(peer_name, "unknown source");

        trace_header_len = snprintf(trace_header, sizeof(trace_header) - 1,
                                    "\n---------------- Read from: %s ---------------\n",
                                    peer_name);

        /* TODO: check actual return value and log error if needed */
        unused_bytes_written = write(tfd, trace_header, (trace_header_len < sizeof(trace_header) - 1)? trace_header_len: (sizeof(trace_header) - 1));
        unused_bytes_written = write(tfd, buf, siz);
        close(tfd);
    }
}
