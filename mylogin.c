/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"


#define TRUE 1
#define FALSE 0
#define LENGTH 20

// Masks all the signals.
void sighandler() {
    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);
}
// Compares a non-encrypted password against an encrypted one.
int compareCrypt(char* password, char* encrypted, char* salt){
    char *temp;
    temp = crypt(password, salt);
    return !strcmp(encrypted, temp);
}


int main(int argc, char *argv[]) {

	mypwent *passwddata; 

	char important1[LENGTH] = "***IMPORTANT 1***";

	char user[LENGTH];

	char important2[LENGTH] = "***IMPORTANT 2***";

	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, 20, stdin) == NULL)
			exit(0);/*   overflow attacks.  */
        strtok(user, "\n");
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
            if (passwddata->pwfailed<20) {
                if (compareCrypt(user_pass, passwddata->passwd, passwddata->passwd_salt)) {

                    // Warn user of failed login attempts.
                    if (passwddata->pwfailed>0) {
                        printf("Number of failed attempts since last login: %d\n",passwddata->pwfailed);
                    }
                    passwddata->pwfailed=0;
                    passwddata->pwage+=1;
                    mysetpwent(passwddata->pwname, passwddata);

                    printf(" You're in !\n");
                    // Warn user if password is old.
                    if (passwddata->pwage>10) {
                        printf(" yo, your password is old man, better change it\n");
                    }
                    // Set the uid to the authenticated user for the running process.
                    setuid(passwddata->uid);
                    // Starts a shell session with the set uid.
                    execve("/bin/sh", NULL, NULL);
                    


                } else {
                    passwddata->pwfailed+=1;
                    mysetpwent(passwddata->pwname, passwddata);
                    printf("Login Incorrect \n");
                }
            }else{
                printf("Too many failed attempts\n");
            }
            
            
		} else {
            printf("No such user \n");
        }
	}
	return 0;
}
