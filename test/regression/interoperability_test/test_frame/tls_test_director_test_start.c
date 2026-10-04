/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

// Portions of this file were generated with AI assistance.

#include "tls_test_frame.h"
#include <dirent.h>
#include <time.h>

/* How long an instance has to end after the director's SIGTERM.  The
   instance's own handler kills its process group and exits at once, so a
   process still there after this did not take the signal.  */
#define TLS_TEST_DIRECTOR_TERMINATE_BOUND_MS    5000

/* The whole dump of one stuck group, every member's stack included, ends
   within this many seconds; members past it get no stack.  */
#ifndef TLS_TEST_DIRECTOR_DUMP_BOUND_S
#define TLS_TEST_DIRECTOR_DUMP_BOUND_S          30
#endif

/* How long the group has to be gone after SIGKILL.  */
#define TLS_TEST_DIRECTOR_REAP_BOUND_MS         2000

/* Set when an instance did not end on SIGTERM within the bound.  */
static INT tls_test_director_stalled;

/* An instance ended by a signal the director did not send it: a crash.  */
#define TLS_TEST_DIRECTOR_CRASH_EXIT            18

/* The signals the director sent, per instance process: its own cleanup is
   not a crash, any other signal is.  Bit 0 SIGTERM, bit 1 SIGKILL.  */
static pid_t tls_test_director_signalled_pid[TLS_TEST_MAX_TEST_INSTANCE_NUMBER];
static INT   tls_test_director_signalled_mask[TLS_TEST_MAX_TEST_INSTANCE_NUMBER];

static void tls_test_director_record_signal(pid_t pid, INT signum)
{
UINT i;
INT  bit = (signum == SIGKILL) ? 2 : 1;

    for (i = 0; i < TLS_TEST_MAX_TEST_INSTANCE_NUMBER; i++)
    {
        if ((tls_test_director_signalled_pid[i] == pid) || (tls_test_director_signalled_pid[i] == 0))
        {
            tls_test_director_signalled_pid[i] = pid;
            tls_test_director_signalled_mask[i] |= bit;
            return;
        }
    }
}

static INT tls_test_director_sent(pid_t pid, INT signum)
{
UINT i;
INT  bit;

    if ((signum != SIGTERM) && (signum != SIGKILL))
    {
        return(0);
    }
    bit = (signum == SIGKILL) ? 2 : 1;
    for (i = 0; i < TLS_TEST_MAX_TEST_INSTANCE_NUMBER; i++)
    {
        if (tls_test_director_signalled_pid[i] == pid)
        {
            return((tls_test_director_signalled_mask[i] & bit) ? 1 : 0);
        }
    }
    return(0);
}

/* Monotonic second at which the current group dump has to stop.  */
static time_t tls_test_director_dump_deadline;

static time_t tls_test_director_now(void)
{
struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return(now.tv_sec);
}

/* The state a stuck instance is in, on stdout: every process in its group,
   per thread the signal masks and the wait channel, then a stack of each
   thread from gdb when the image has it.  Nothing from the environment.  */
static void tls_test_director_dump_task(const char *task_dir)
{
FILE *f;
char  path[300];
char  line[256];

    snprintf(path, sizeof(path), "%s/status", task_dir);
    f = fopen(path, "r");
    if (f)
    {
        while (fgets(line, sizeof(line), f))
        {
            if (!strncmp(line, "Name:", 5) || !strncmp(line, "State:", 6) ||
                !strncmp(line, "SigPnd:", 7) || !strncmp(line, "ShdPnd:", 7) ||
                !strncmp(line, "SigBlk:", 7) || !strncmp(line, "SigIgn:", 7) ||
                !strncmp(line, "SigCgt:", 7))
            {
                printf("    %s", line);
            }
        }
        fclose(f);
    }
    snprintf(path, sizeof(path), "%s/wchan", task_dir);
    f = fopen(path, "r");
    if (f)
    {
        if (fgets(line, sizeof(line), f))
        {
            printf("    wchan:\t%s\n", line);
        }
        fclose(f);
    }
}

static void tls_test_director_dump_process(pid_t pid)
{
char           path[300];
DIR           *tasks;
struct dirent *task;
pid_t          gdb_pid;
int            gdb_status;
char           pid_string[16];
char           seconds[16];
time_t         left;

    printf("  process %d\n", (int)pid);
    snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
    tasks = opendir(path);
    if (tasks == NULL)
    {
        printf("    (gone)\n");
        return;
    }
    while ((task = readdir(tasks)) != NULL)
    {
        if (task -> d_name[0] == '.')
        {
            continue;
        }
        snprintf(path, sizeof(path), "/proc/%d/task/%s", (int)pid, task -> d_name);
        printf("   thread %s\n", task -> d_name);
        tls_test_director_dump_task(path);
    }
    closedir(tasks);
    fflush(stdout);

    left = tls_test_director_dump_deadline - tls_test_director_now();
    if (left <= 0)
    {
        printf("    (stack skipped: the %d s deadline for the whole group dump has passed)\n",
               TLS_TEST_DIRECTOR_DUMP_BOUND_S);
        fflush(stdout);
        return;
    }

    snprintf(pid_string, sizeof(pid_string), "%d", (int)pid);
    snprintf(seconds, sizeof(seconds), "%ld", (long)left);
    gdb_pid = fork();
    if (gdb_pid == 0)
    {
        dup2(STDOUT_FILENO, STDERR_FILENO);
        /* No frame arguments, no entry values, no locals: a frame's
           arguments and strings could carry key or credential material.
           Function names and addresses only.  gdb itself is bounded, and
           killed if it does not stop.  */
        execlp("timeout", "timeout", "-k", "5", seconds, "gdb", "-batch", "-nx", "-p", pid_string,
               "-ex", "set debuginfod enabled off",
               "-ex", "set print frame-arguments none",
               "-ex", "set print entry-values no",
               "-ex", "set print address on",
               "-ex", "thread apply all bt", (char *)NULL);
        printf("    (no stack: timeout/gdb could not be run)\n");
        _exit(127);
    }
    if (gdb_pid > 0)
    {
        waitpid(gdb_pid, &gdb_status, 0);
        if (WIFEXITED(gdb_status) && (WEXITSTATUS(gdb_status) == 127))
        {
            printf("    (no stack: gdb is not installed)\n");
        }
    }
    fflush(stdout);
}

static void tls_test_director_dump_group(pid_t pgid)
{
DIR           *procs;
struct dirent *proc;
char           path[300];
FILE          *f;
int            pid, ppid, group;
char           comm[64];
char           state;

    printf("TLS_TEST_DIRECTOR: instance group %d did not end within %d ms of SIGTERM\n",
           (int)pgid, TLS_TEST_DIRECTOR_TERMINATE_BOUND_MS);
    tls_test_director_dump_deadline = tls_test_director_now() + TLS_TEST_DIRECTOR_DUMP_BOUND_S;
    procs = opendir("/proc");
    if (procs == NULL)
    {
        tls_test_director_dump_process(pgid);
        return;
    }
    while ((proc = readdir(procs)) != NULL)
    {
        if ((proc -> d_name[0] < '0') || (proc -> d_name[0] > '9'))
        {
            continue;
        }
        snprintf(path, sizeof(path), "/proc/%s/stat", proc -> d_name);
        f = fopen(path, "r");
        if (f == NULL)
        {
            continue;
        }
        if ((fscanf(f, "%d (%63[^)]) %c %d %d", &pid, comm, &state, &ppid, &group) == 5) &&
            (group == (int)pgid))
        {
            fclose(f);
            printf(" %s (%c)\n", comm, state);
            tls_test_director_dump_process((pid_t)pid);
            continue;
        }
        fclose(f);
    }
    closedir(procs);
}

/* After SIGKILL: reap what of the group is the director's own (the leader),
   within a bound, then confirm through /proc that no member is left; the
   instance's own children are not the director's to reap.  Members still
   there are reported.  */
static INT tls_test_director_reap_group(pid_t pgid, INT *exit_status_ptr)
{
INT             status;
INT             waited;
INT             leader_reaped = 0;
pid_t           got;
struct timespec tick = { 0, 50L * 1000L * 1000L };
DIR            *procs;
struct dirent  *proc;
char            path[300];
FILE           *f;
int             pid, ppid, group;
char            comm[64];
char            state;
INT             left_over = 0;

    for (waited = 0; waited < TLS_TEST_DIRECTOR_REAP_BOUND_MS; waited += 50)
    {
        got = waitpid(-pgid, &status, WNOHANG);
        if (got == pgid)
        {
            *exit_status_ptr = status;
            leader_reaped = 1;
            continue;
        }
        if (got > 0)
        {
            continue;
        }
        if ((got == -1) && (errno == ECHILD))
        {
            break;
        }
        nanosleep(&tick, NULL);
    }

    procs = opendir("/proc");
    if (procs != NULL)
    {
        while ((proc = readdir(procs)) != NULL)
        {
            if ((proc -> d_name[0] < '0') || (proc -> d_name[0] > '9'))
            {
                continue;
            }
            snprintf(path, sizeof(path), "/proc/%s/stat", proc -> d_name);
            f = fopen(path, "r");
            if (f == NULL)
            {
                continue;
            }
            if ((fscanf(f, "%d (%63[^)]) %c %d %d", &pid, comm, &state, &ppid, &group) == 5) &&
                (group == (int)pgid) && (state != 'Z'))
            {
                printf("TLS_TEST_DIRECTOR: group %d member %d (%s, state %c) still there after SIGKILL\n",
                       (int)pgid, pid, comm, state);
                left_over++;
            }
            fclose(f);
        }
        closedir(procs);
    }
    printf("TLS_TEST_DIRECTOR: group %d after SIGKILL: leader %s, %d member(s) left\n",
           (int)pgid, leader_reaped ? "reaped" : "NOT reaped", left_over);
    fflush(stdout);

    return(leader_reaped ? 0 : -1);
}

/* SIGTERM an instance's process group and reap the instance, within a
   bound.  An instance that does not end is dumped, killed with SIGKILL and
   recorded as a stall, which fails the test.  */
static INT tls_test_director_terminate(TLS_TEST_INSTANCE *instance_ptr, INT *exit_status_ptr)
{
pid_t           pid = instance_ptr -> tls_test_instance_current_pid;
pid_t           got;
INT             waited;
struct timespec tick = { 0, 100L * 1000L * 1000L };

    tls_test_director_record_signal(pid, SIGTERM);
    if (-1 == kill(-pid, SIGTERM))
    {
        return(-1);
    }
    for (waited = 0; waited < TLS_TEST_DIRECTOR_TERMINATE_BOUND_MS; waited += 100)
    {
        got = waitpid(pid, exit_status_ptr, WNOHANG);
        if (got == pid)
        {
            return(0);
        }
        if (got == -1)
        {
            return(-1);
        }
        nanosleep(&tick, NULL);
    }

    tls_test_director_stalled = 1;
    tls_test_director_dump_group(pid);

    /* Whatever the dump did.  */
    tls_test_director_record_signal(pid, SIGKILL);
    kill(-pid, SIGKILL);
    return(tls_test_director_reap_group(pid, exit_status_ptr));
}

static void signal_handler_wait_all( int signum)
{
    /* Wait for all processes in current process group. */
    while ( -1 != wait(NULL));

    /* Send the same signal to the whole process, now with its default
       action.  raise() would direct it at this thread alone, which cannot
       act on it until this handler returns; a ThreadX port thread can be
       suspended inside the handler and never return.  */
    kill( getpid(), signum);
}

static void signal_handler_kill_process_group( int signum)
{
    /* Install an one shot signal handler. */
    struct sigaction sig_act;
    memset( &sig_act, 0, sizeof(sig_act));
    sigfillset( &sig_act.sa_mask);
    sig_act.sa_handler = signal_handler_wait_all;
    sig_act.sa_flags = SA_RESETHAND;
    sigaction( signum, &sig_act, NULL);

    /* Send received signal to every process in current process group. */
    kill( 0, signum);
}

/* Run test programs. */
INT tls_test_director_test_start( TLS_TEST_DIRECTOR* director_ptr)
{
pid_t pid;
TLS_TEST_INSTANCE* iter, *iter_term, *iter_wait;
INT status = TLS_TEST_SUCCESS, exit_status = 0;
int err = 0;

    /* Check parameters. */
    return_value_if_fail( NULL != director_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( 0 != director_ptr -> tls_test_registered_test_instances, TLS_TEST_NO_REGISTERED_INSTANCE);

    /* Get the first instance. */
    iter = director_ptr -> tls_test_first_instance_ptr;

    /* Loop to launch all test instances. */
    while ( NULL != iter)
    {

        /* Launch next test instance after given seconds. */
        if ( iter -> tls_test_delay)
        {
            sleep(iter -> tls_test_delay);
        }

        pid = fork();

        /* Error handle. */
        show_error_message_if_fail( -1 != pid);
        if ( -1 == pid)
        {
            /* Cleanup all running test process if fail to fork a new process for the new instance. */
            for ( iter_term = director_ptr -> tls_test_first_instance_ptr; iter_term != iter; tls_test_instance_find_next( iter_term, &iter_term))
            {
                /* Kill the process group of the test instance and reap it,
                   within a bound.  */
                status = tls_test_director_terminate( iter_term, &exit_status);
                show_error_message_if_fail( -1 != status);
                if ( -1 == status)
                    continue;

                status = tls_test_instance_set_exit_status( iter_term, exit_status);
                return_value_if_fail( TLS_TEST_SUCCESS == status, status);

            } /* for iter_term */

            return TLS_TEST_UNABLE_TO_CREATE_TEST_PROCESS;
        } /* if -1 == pid */

        /* Child process. */
        else if (0 == pid)
        {

            /* Create a new process group. */
            setpgid( 0, 0);

            /* Install signal handler for SIGALRM and SIGTERM. */
            struct sigaction sig_act;
            /* Block every other signal while a handler runs, so that the
               ThreadX port's suspend signal cannot park it.  */
            memset( &sig_act, 0, sizeof(sig_act));
            status = sigfillset( &sig_act.sa_mask);
            return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
            sig_act.sa_handler = signal_handler_kill_process_group;    /* Specify signal handler. */
            sig_act.sa_flags = SA_RESETHAND;                /* Set the signal handler as a one shot handler. */
            status = sigaction( SIGALRM, &sig_act, NULL);
            return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
            status = sigaction( SIGTERM, &sig_act, NULL);
            return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

            /* Set timeer for the test process. */
            alarm( iter -> tls_test_timeout);

            /* Enter test entry. */
            status = iter -> tls_test_entry( iter); 

            /* Wait until all child process terminated. */
            tls_test_wait_all_child_process( NULL);

            exit( status);
        }
        /* Parent process. */
        else
        {
            /* Set the gid of the child process again. */
            setpgid( pid, pid);

            iter -> tls_test_instance_current_pid = pid;
            iter -> tls_test_instance_status |= TLS_TEST_INSTANCE_STATUS_RUNNING;
            tls_test_instance_find_next( iter, &iter);
        }
    } /* NULL != iter */

    /* Wait for all test instances. */
    iter_wait = director_ptr -> tls_test_first_instance_ptr;
    while (iter_wait != NULL && TLS_TEST_SUCCESS == ( status = tls_test_uninterruptable_wait( &pid, &exit_status)))
    {
        iter = director_ptr -> tls_test_first_instance_ptr;
        while ( NULL != iter)
        {
            if (iter -> tls_test_instance_current_pid == pid)
            {
                status = tls_test_instance_set_exit_status( iter, exit_status);
                show_error_message_if_fail( TLS_TEST_SUCCESS == status);
                if (iter -> tls_test_instance_exit_status != TLS_TEST_SUCCESS)
                {
                    err = 1;
                }

                break; /* NULL != iter */
            } /* if iter -> tls_test_instance_current_pid == pid */

            tls_test_instance_find_next( iter, &iter);
        } /* NULL != iter */

        if (err == 1)
        {
            for (iter_term = director_ptr -> tls_test_first_instance_ptr; iter_term != NULL;)
            {
                if (iter != iter_term)
                {
                    /* Kill the process group of the test instance and reap
                       it, within a bound.  */
                    status = tls_test_director_terminate(iter_term, &exit_status);
                    show_error_message_if_fail(-1 != status);
                    if (-1 != status)
                    {
                        status = tls_test_instance_set_exit_status(iter_term, exit_status);
                        return_value_if_fail(TLS_TEST_SUCCESS == status, status);
                    }
                }
                tls_test_instance_find_next( iter_term, &iter_term);
            }
            break;
        }
        tls_test_instance_find_next(iter_wait, &iter_wait);
    } /* while exited_test_intances < director_ptr -> tls_tset_registered_test_instances */

    /* An instance its own alarm ended, or one that did not end on SIGTERM,
       stalled.  That is a failure whatever the other instance returned: a
       skip (TLS_TEST_NOT_AVAILABLE) or a success from the other side must not
       hide it, and the callers' exit status logic would.  So it ends here,
       with a status the ctest command does not accept.  */
    /* An instance ended by any other signal the director did not send it
       (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, or a SIGTERM or SIGKILL from
       elsewhere) crashed.  That wins over a skip or a success from the other
       instance too.  The director's own SIGTERM, and its SIGKILL after a
       stall, are cleanup.  */
    {
        INT crashed = 0;

        for (iter = director_ptr -> tls_test_first_instance_ptr; iter != NULL; tls_test_instance_find_next(iter, &iter))
        {
            INT signum;

            if (!(iter -> tls_test_instance_status & TLS_TEST_INSTANCE_STATUS_SIGNALED))
            {
                continue;
            }
            signum = -(iter -> tls_test_instance_exit_status);
            if ((signum == SIGALRM) || tls_test_director_sent(iter -> tls_test_instance_current_pid, signum))
            {
                continue;
            }
            printf("TLS_TEST_DIRECTOR: instance %s (pid %d) died from signal %d (%s), not sent by the director\n",
                   iter -> tls_test_instance_name, (int)iter -> tls_test_instance_current_pid,
                   signum, strsignal(signum));
            crashed = 1;
        }
        if (crashed)
        {
            printf("TLS_TEST_DIRECTOR: FAIL, a test instance crashed (exit %d)\n", TLS_TEST_DIRECTOR_CRASH_EXIT);
            fflush(stdout);
            exit(TLS_TEST_DIRECTOR_CRASH_EXIT);
        }
    }

    for (iter = director_ptr -> tls_test_first_instance_ptr; iter != NULL; tls_test_instance_find_next(iter, &iter))
    {
        if ((iter -> tls_test_instance_status & TLS_TEST_INSTANCE_STATUS_SIGNALED) &&
            (iter -> tls_test_instance_exit_status == -SIGALRM))
        {
            printf("TLS_TEST_DIRECTOR: instance %s was ended by its %u s alarm\n",
                   iter -> tls_test_instance_name, (unsigned)iter -> tls_test_timeout);
            tls_test_director_stalled = 1;
        }
    }
    if (tls_test_director_stalled)
    {
        printf("TLS_TEST_DIRECTOR: FAIL, a test instance stalled (exit %d)\n", TLS_TEST_INSTANCE_NO_TIME_LEFT);
        fflush(stdout);
        exit(TLS_TEST_INSTANCE_NO_TIME_LEFT);
    }

    return TLS_TEST_SUCCESS;
}
