#include "boinc_api.h"
#include "diagnostics.h"
#include "filesys.h"
#include "util.h"
#include "error_numbers.h"
#include "proc_control.h"

#ifdef _WIN32
// Nothing extra yet
#else
#include <sys/stat.h>     // stat()
#include <sys/wait.h>     // waitpid()
#include <sys/resource.h> // setpriority() flags
#include <unistd.h>       // read()
#include <fcntl.h>        // fcntl()
#endif

using namespace std;

#ifdef _WIN32
static DWORD  pid;
static HANDLE pid_handle, thread_handle;
static HANDLE hChildStdoutRd;
#else
static pid_t pid;
static int   hChildStdoutRd;
#endif
static bool app_suspended;

static double ratio_done = -1.0;   // negative mean unknown
static double initial_cpu_time;
static double checkpoint_offset;   // when app checkpointed (in this session)
static bool   status_updated;      // must report new info
static bool   range_complete;

static vector<string> vs_ExtraParams;

static string quote_spaces(string s)
{
    if (s.find(' ') == string::npos)
        return s;
    return "\"" + s + "\"";
}

static int run_application(void)
{
    string sInputFile, sMainProgram;

    // required - main program
    // a) old style executable (for compatibility with old tasks, could be removed later)
    DIRREF dir = dir_open(".");
    if (dir)
    {
        char file[512];
        while (dir_scan(file, dir, sizeof(file)) == 0)
        {
            if (strstr(file, "primegrid_sr2sieve_1.")     == file ||
                strstr(file, "primegrid_pps_sr2sieve_1.") == file ||
                strstr(file, "primegrid_psp_sr2sieve_1.") == file
               )
            {
                boinc_resolve_filename_s(file, sMainProgram);
                break;
            }
        }
        dir_close(dir);
    }
    // b) if old style exe not found, try new style
    if (sMainProgram.empty())
        boinc_resolve_filename_s("sieve_program", sMainProgram);
    // optional - a file with full command line (magic name read by sr2sieve)
    boinc_resolve_filename_s("cmd", sInputFile);
    boinc_copy(sInputFile.c_str(), "sr2sieve-command-line.txt");
    // optional - input sieve (old style), "-i input.txt" specified on command line
    boinc_resolve_filename_s("in", sInputFile);
    boinc_copy(sInputFile.c_str(), "input.txt");
    // optional - input sieve (new style), automatically add cmdline option "-i <file>"
    boinc_resolve_filename_s("in_v2", sInputFile);
    if (boinc_file_exists(sInputFile.c_str()))
    {
        vs_ExtraParams.push_back("-i");
        vs_ExtraParams.push_back(quote_spaces(sInputFile));
    }

    string arguments;
    unsigned u;

    // Must have argv[0] in arguments for both Windows and Linux
    arguments = quote_spaces(sMainProgram);
    // Append extra command line
    for (u = 0; u < vs_ExtraParams.size(); u++)
    {
        arguments += " ";
        arguments += vs_ExtraParams[u];
    }
    fprintf(stderr, "running %s\n", arguments.c_str());

    // The Unicode version of CreateProcessW can modify the contents of lpCommandLine.
    // parse_command_line() from Boinc library WILL modify argument string.
    // So make a copy.
    char *args = strdup(arguments.c_str());

#ifdef _WIN32
    PROCESS_INFORMATION process_info;
    STARTUPINFO startup_info;
    SECURITY_ATTRIBUTES sa;

    memset(&process_info, 0, sizeof(process_info));
    memset(&startup_info, 0, sizeof(startup_info));

    // Create pipe to redirect child' stdout
    // Set the bInheritHandle flag so pipe handles are inherited
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    // Create a pipe for the child process's STDOUT.
    HANDLE hChildStdoutWr;
    if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &sa, 0))
    {
        fprintf(stderr, "Stdout pipe creation failed\n");
        return ERR_PIPE;
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    // pass pipe as stdout for app. OK to keep current stderr (saved to our stderr.txt)
    startup_info.cb         = sizeof(startup_info);
    startup_info.dwFlags    = STARTF_USESTDHANDLES;
    startup_info.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    startup_info.hStdOutput = hChildStdoutWr;
    startup_info.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    if (!CreateProcess(
        sMainProgram.c_str(),
        args,
        NULL,
        NULL,
        TRUE,  // inherit handles
        CREATE_NO_WINDOW | IDLE_PRIORITY_CLASS,
        NULL,
        NULL,
        &startup_info,
        &process_info
    )) {
        free(args);
        return ERR_EXEC;
    }
    free(args);
    pid           = process_info.dwProcessId;
    pid_handle    = process_info.hProcess;
    thread_handle = process_info.hThread;
#else
    // Parse command line (with quotes) and build array of arguments
    #define MAX_ARGS_ARRAY_SIZE 256
    static char *args_array[MAX_ARGS_ARRAY_SIZE];
    int cnt;
    // Danger: Boinc lib function do not check array size
    cnt = parse_command_line(args, args_array);
    if (cnt >= MAX_ARGS_ARRAY_SIZE)  // buffer overrun. quit asap if not dead yet
        _exit(EXIT_OUT_OF_MEMORY);

#ifdef VERBOSE
    int i;
    for (i = 0; i < cnt; i++)
        fprintf(stderr, "[%d] = [%s]\n", i, args_array[i]);
#endif

    // Create handles to redirect output
    int fd_out[2];
    if (pipe(fd_out) < 0)
    {
        perror("can't pipe");
        return ERR_PIPE;
    }
    pid = fork();
    if (pid == -1)
    {
        perror("can't fork");
        return ERR_FORK;
    }
    if (pid == 0)  // child
    {
        // redirect stdout to pipe (stderr still goes to stderr.txt)
        close(fd_out[0]);
        if (dup2(fd_out[1], STDOUT_FILENO) == -1)
            perror("dup2 in child");
        if (setpriority(PRIO_PROCESS, 0, PROCESS_IDLE_PRIORITY) == -1)
            perror("setpriority in child");
        execv(sMainProgram.c_str(), args_array);
        // can be here only if exec failed
        perror("exec in child");
        exit(EXIT_CHILD_FAILED);
    }

    // parent. save handle to read end of pipe
    hChildStdoutRd = fd_out[0];
    close(fd_out[1]);

    // set read end of pipe to non-blocking mode
    int flags = fcntl(hChildStdoutRd, F_GETFL);
    if (flags == -1)
        perror("fcntl(get)");
    else if (fcntl(hChildStdoutRd, F_SETFL, flags | O_NONBLOCK) == -1)
        perror("fcntl(set)");
#endif
    return 0;
}

//
// on error, return false and keep old cpu_time
//
static bool get_child_cpu_time(double& cpu_time)
{
    double t;
#ifdef _WIN32
    // return -1 on error
    if (boinc_process_cpu_time(pid_handle, t) < 0)
        return false;
#else
    // return zero time on error
    t = linux_cpu_time(pid);
    if (t == 0)
        return false;
#endif
    cpu_time = t;
    return true;
}

static void poll_child_stdout()
{
    static bool closed;
    static char buf[512];
    static unsigned len;

    for (;;)
    {
        // split input stream as strings, separated by \r or \n
        buf[len] = 0;
        char *end = strpbrk(buf, "\r\n");
        // if no \n but buffer is full, accept it as truncated string
        if (end == NULL && len >= sizeof(buf)-1)
        {
            len = sizeof(buf);  // for correct purge of last zero below
            end = buf + sizeof(buf) - 1;
        }
        if (end)
        {
            char *pat;

            // got complete line
            *end = 0;
            // parse line contents
            if (*buf == 0)
            {
                // empty line, ignored
            }
            else if (isdigit(*buf) && strstr(buf, " | ") && strchr(buf, '^')) // factor, like "109037563 | 3*2^41396435-1"
            {
                // ignore it
            }
            // status line: p=110499161, 1000564 p/sec, 47 factors, 10.5% done, ...
            // status line: p=110499161, 1000564 p/sec, 1 factor, 10.5% done, ...  (ouch...)
            else if (buf[0] == 'p' && buf[1] == '=' && isdigit(buf[2]) &&
                     ( (pat = strstr(buf, " factors, ")) != NULL || (pat = strstr(buf, " factor, ")) != NULL )
                    )
            {
                pat = strchr(pat, ',') + 2;   // guaranteed to be non-NULL, patterns above always ends with comma and space
                ratio_done     = atof(pat) / 100;
                status_updated = true;
#ifdef VERBOSE
                fprintf(stderr, "done: %f\n", ratio_done);
#endif
            }
            else
            {
                if (strstr(buf, "because range is complete"))
                {
                    fprintf(stderr, "Detected range complete\n");
                    range_complete = true;
                    ratio_done     = 1.0;
                    status_updated = true;
                }
                // everything else copied to our stderr log
                fprintf(stderr, "%s\n", buf);
            }

            // remove processed portion of string
            end++;  // remove last zero too
            len -= end - buf;
            if (len)
                memmove(buf, end, len);
            // parse more strings, if exist
            continue;
        }

        // append more data from pipe, if possible
        if (closed)
            break;
#ifdef _WIN32
        DWORD gotBytes = 0;
        if (!PeekNamedPipe(hChildStdoutRd, NULL, 0, NULL, &gotBytes, NULL))
        {
            closed = true; // child process terminated
            break;
        }
        if (!gotBytes) // no data available
            break;
        if (!ReadFile(hChildStdoutRd, buf + len, sizeof(buf)-len-1, &gotBytes, NULL))
        {
            fprintf(stderr, "pipe ReadFile(): error 0x%lx\n", GetLastError());
            closed = true;
            break;
        }
        len += gotBytes;
#else
        ssize_t gotBytes;
        gotBytes = read(hChildStdoutRd, buf + len, sizeof(buf)-len-1);
        if (gotBytes < 0)   // error
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)  // really, no data yet
                gotBytes = 0;
            else
            {
                perror("pipe read");
                closed = true;
            }
        }
        if (gotBytes <= 0)  // error or no data available
            break;
        len += gotBytes;
#endif
        // back to parsing loop
    }
}

// Since app does checkpointing in background, monitor modification time
// of checkpoint file. On change, assume that app has checkpointed.
static void poll_checkpoint_file(bool report)
{
    static time_t last_time;
    struct stat st;
    static const char file[] = "checkpoint.txt";

    if (stat(file, &st) == 0 && st.st_size != 0 && st.st_mtime != last_time)
    {
        last_time = st.st_mtime;
        if (report)
        {
            get_child_cpu_time(checkpoint_offset);
            status_updated = true;
#ifdef VERBOSE
            fprintf(stderr, "App checkpointed at %f\n", checkpoint_offset);
#endif
        }
    }
}

static bool poll_application(int& status)
{
#ifdef _WIN32
    DWORD exit_code;
    if (GetExitCodeProcess(pid_handle, &exit_code))
    {
        if (exit_code == STILL_ACTIVE)
            return false;
        status = exit_code;
        return true;
    }
#else
    pid_t wpid;
    int   stat;
    wpid = waitpid(pid, &stat, WNOHANG);
    if (wpid == 0)
        return false;
    if (wpid > 0)
    {
        status = WEXITSTATUS(stat);
        return true;
    }
#endif
    // Cannot get status. May be do something here.
    return false;
}

static void resume_app()
{
    fprintf(stderr, "Resuming\n");
    suspend_or_resume_process(pid, true);
}

static void stop_app()
{
    fprintf(stderr, "Suspending\n");
    suspend_or_resume_process(pid, false);
}

// kill this task (gracefully if possible) and any other subprocesses
// Linux Boinc lib sends SIGTERM, it's OK for sr2sieve
static void kill_app()
{
    fprintf(stderr, "Killing\n");
#ifdef _WIN32
    kill_descendants();
#else
    // be sure that app is not SIGSTOP'ed and signal handlers could run for graceful shutdown
    if (app_suspended)
        resume_app();
    kill_descendants(pid);
#endif
    poll_child_stdout();   // get remaining messages for logging
    // sr2sieve bug: no output after signal if stdout is redirected, only console works.
    // easy to confirm with 'sr2sieve ... >file' and Ctrl-C
}

// MUST kill app gracefully for correct shutdown and checkpointing
// For sr2sieve, it's OK to use kill_app() (SIGTERM)
static void terminate_app()
{
    kill_app();
}

static void poll_boinc_messages()
{
    BOINC_STATUS status;
    boinc_get_status(&status);
    if (status.no_heartbeat)
    {
        fprintf(stderr, "Terminating - no heartbeat\n");
        terminate_app();
        exit(0);
    }
    if (status.quit_request)
    {
        fprintf(stderr, "Terminating - quit request\n");
        terminate_app();
        exit(0);
    }
    if (status.abort_request)
    {
        fprintf(stderr, "Terminating - abort request\n");
        kill_app();
        exit(EXIT_ABORTED_BY_CLIENT);
    }
    if ( status.suspended && !app_suspended)
    {
        stop_app();
        app_suspended = true;
    }
    if (!status.suspended &&  app_suspended)
    {
        resume_app();
        app_suspended = false;
    }
}

static void send_status_message()
{
    if (status_updated && ratio_done >= 0)
    {
        static double session_time;  // keep old time on error

        get_child_cpu_time(session_time);  // unchanged on error
        boinc_report_app_status(initial_cpu_time + session_time,
                                initial_cpu_time + checkpoint_offset,
                                ratio_done
                               );
        status_updated = false;
    }
}

//
// Poor man's getopt()
//
static bool parse_cmdline(int argc, char **argv)
{
    static const char optstring[] = "?hc:";
    int i;

    for (i = 1; i < argc; i++)
    {
        char *opt = argv[i];
        const char *idx;
        char optchar;
        char *optarg = NULL;

        if (opt[0] != '-' || (idx = strchr(optstring, (optchar = opt[1]))) == NULL || opt[2] != 0)
        {
            fprintf(stderr, "Unknown option '%s'. Use '-h' for help\n", opt);
            return false;
        }
        if (idx[1] == ':')
        {
            if (++i >= argc)
            {
                fprintf(stderr, "Option '%s' requires an argument\n", opt);
                boinc_finish(EXIT_INIT_FAILURE);
            }
            optarg = argv[i];
        }

        static const char usage_text[] =
            "Supported options:\n\n"
            "-c <text>      -- extra command line parameters for main program\n"
            "                  (may be repeated)\n"
            "\n"
            ;

        switch (optchar)
        {
        case 'c':
            vs_ExtraParams.push_back(optarg);
            break;
        default:
            fprintf(stderr, usage_text);
            fprintf(stdout, usage_text);  // also show to user because stderr redirected to file
            return false;
        }
    }
    return true;
}

int main(int argc, char** argv)
{
    BOINC_OPTIONS options;
    int retval;

    boinc_init_diagnostics(
        BOINC_DIAG_DUMPCALLSTACKENABLED |
        BOINC_DIAG_HEAPCHECKENABLED |
        BOINC_DIAG_TRACETOSTDERR |
        BOINC_DIAG_REDIRECTSTDERR
    );

    fprintf(stderr, "BOINC sr2sieve wrapper 2.00\n");

    memset(&options, 0, sizeof(options));
    options.main_program = true;
    options.check_heartbeat = true;
    options.handle_process_control = true;
    boinc_init_options(&options);

    if (parse_cmdline(argc, argv) == false)
        boinc_finish(EXIT_INIT_FAILURE);

    // Workaround for "finish file present too long" problem
    if (boinc_file_exists("boinc_finish_called"))
    {
        fprintf(stderr, "The job is already completed\n");
        exit(0);  // standard exit. boinc_finish was already done early
    }

    // get CPU time spent in previous sessions (really, until checkpoint from which we'll continue)
    boinc_wu_cpu_time(initial_cpu_time);
    // get initial timestamp of checkpoint file, if exist
    poll_checkpoint_file(false);

    retval = run_application();
    if (retval)
    {
        fprintf(stderr, "can't run app: %d\n", retval);
        boinc_finish(retval);
    }

    // Main monitoring loop

    int status;
    for (;;)
    {
        bool terminated;

        terminated = poll_application(status);

        // even if terminated, get remaining app output and send messages
        poll_child_stdout();
        poll_checkpoint_file(true);
        send_status_message();

        if (terminated)
            break;

        // finally, process control messages from client
        poll_boinc_messages();
        boinc_sleep(1.);
    }

    // Postprocess results

    string sResultFile;
    boinc_resolve_filename_s("psp_sr2sieve.out", sResultFile);

    static const char factors_file[] = "factors.txt";
    if (boinc_file_exists(factors_file))
    {
        fprintf(stderr, "Factors file found\n");
        retval = boinc_copy(factors_file, sResultFile.c_str());
        if (retval)
        {
            fprintf(stderr, "can't copy factors: %d\n", retval);
            status = retval;
        }
    }
    else
    {
        if (range_complete)
        {
            FILE *f = boinc_fopen(sResultFile.c_str(), "w");
            if (f)
            {
                fprintf(stderr, "Factors file not found\n");
                fprintf(f, "no factors");
                fclose(f);
            }
            else
                fprintf(stderr, "Cannot write fake factor file\n");
        }
        else
            fprintf(stderr, "No factors file and range not complete\n");
    }

    // Done
    boinc_finish(status);
    return status;
}
