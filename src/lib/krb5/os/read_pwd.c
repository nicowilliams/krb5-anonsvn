/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * libos: krb5_read_password for BSD 4.3
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_read_pwd_c[] =
"$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include <krb5/krb5.h>

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include <krb5/ext-proto.h>

/* POSIX_* are auto-magically defined in <krb5/config.h> at source
   configuration time. */

#ifdef POSIX_TERMIOS
#include <termios.h>
#else
#include <sys/ioctl.h>
#endif /* POSIX_TERMIOS */

extern int errno;

#ifdef POSIX_TERMIOS
#define cleanup(errcode) (void) signal(SIGINT, ointrfunc); tcsetattr(0, TCSANOW, &save_control); return errcode;
#else
#define cleanup(errcode) (void) signal(SIGINT, ointrfunc); ioctl(0, TIOCSETP, (char *)&tty_savestate); return errcode;
#endif

static jmp_buf pwd_jump;


static krb5_sigtype
intr_routine()
{
    longjmp(pwd_jump, 1);
    /*NOTREACHED*/
}

krb5_error_code
krb5_read_password(prompt, prompt2, return_pwd, size_return)
char *prompt;
char *prompt2;
char *return_pwd;
int *size_return;
{
    /* adapted from Kerberos v4 des/read_password.c */

    char *readin_string = 0;
    register char *ptr;
    int scratchchar;
    krb5_sigtype (*ointrfunc)();
#ifdef POSIX_TERMIOS
    struct termios echo_control, save_control;

    if (tcgetattr(0, &echo_control) == -1)
	return errno;

    save_control = echo_control;
    echo_control.c_lflag &= ~(ECHO|ECHONL);
    
    if (tcsetattr(0, TCSANOW, &echo_control) == -1)
	return errno;
#else
    /* 4.3BSD style */
    struct sgttyb tty_state, tty_savestate;

    /* save terminal state */
    if (ioctl(0,TIOCGETP,(char *)&tty_savestate) == -1) 
	return errno;

    tty_state = tty_savestate;

    tty_state.sg_flags &= ~ECHO;
    if (ioctl(0,TIOCSETP,(char *)&tty_state) == -1)
	return errno;
#endif

    if (setjmp(pwd_jump)) {
	/* interrupted */
	if (readin_string) {
	    (void) memset(readin_string, 0, *size_return);
	    free(readin_string);
	}
	(void) memset(return_pwd, 0, *size_return);
	cleanup(KRB5_LIBOS_PWDINTR);
    }
    /* save intrfunc */
    ointrfunc = signal(SIGINT, intr_routine);

    /* put out the prompt */
    (void) fputs(prompt,stdout);
    (void) fflush(stdout);
    (void) memset(return_pwd, 0, *size_return);

    if (fgets(return_pwd, *size_return, stdin) == NULL) {
	/* error */
	(void) putchar('\n');
	(void) memset(return_pwd, 0, *size_return);
	cleanup(KRB5_LIBOS_CANTREADPWD);
    }
    (void) putchar('\n');
    /* fgets always null-terminates the returned string */

    /* replace newline with null */
    if (ptr = strchr(return_pwd, '\n'))
	*ptr = '\0';
    else /* flush rest of input line */
	do {
	    scratchchar = getchar();
	} while (scratchchar != EOF && scratchchar != '\n');

    if (prompt2) {
	/* put out the prompt */
	(void) fputs(prompt2,stdout);
	(void) fflush(stdout);
	readin_string = malloc(*size_return);
	if (!readin_string) {
	    (void) memset(return_pwd, 0, *size_return);
	    cleanup(ENOMEM);
	}
	(void) memset(readin_string, 0, *size_return);
	if (fgets(readin_string, *size_return, stdin) == NULL) {
	    /* error */
	    (void) putchar('\n');
	    (void) memset(readin_string, 0, *size_return);
	    (void) memset(return_pwd, 0, *size_return);
	    free(readin_string);
	    cleanup(KRB5_LIBOS_CANTREADPWD);
	}
	(void) putchar('\n');

	if (ptr = strchr(readin_string, '\n'))
	    *ptr = '\0';
        else /* need to flush */
	    do {
		scratchchar = getchar();
	    } while (scratchchar != EOF && scratchchar != '\n');
	    
	/* compare */
	if (strncmp(return_pwd, readin_string, *size_return)) {
	    (void) memset(readin_string, 0, *size_return);
	    (void) memset(return_pwd, 0, *size_return);
	    free(readin_string);
	    cleanup(KRB5_LIBOS_BADPWDMATCH);
	}
	(void) memset(readin_string, 0, *size_return);
	free(readin_string);
    }
    
    /* reset intrfunc */
    (void) signal(SIGINT, ointrfunc);

#ifdef POSIX_TERMIOS
    if (tcsetattr(0, TCSANOW, &save_control) == -1)
	return errno;
#else
    if (ioctl(0, TIOCSETP, (char *)&tty_savestate) == -1)
	return errno;
#endif
    *size_return = strlen(return_pwd);

    return 0;
}
