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

#define API_VERSION (BOINC_MAJOR_VERSION * 10000 + BOINC_MINOR_VERSION * 100 + BOINC_RELEASE)

using namespace std;

#ifdef _WIN32
static DWORD  pid;
static HANDLE pid_handle;
static HANDLE hChildStdoutRd = INVALID_HANDLE_VALUE;
#else
static pid_t pid;
static int   hChildStdoutRd = -1;
#endif
static bool app_suspended;

static double ratio_done = -1.0;   // negative mean unknown
static double initial_cpu_time;
static double final_cpu_time;      // optional, obtained when app terminates
static double checkpoint_offset;   // when app checkpointed (in this session)
static bool   status_updated;      // must report new info
static unsigned num_threads;       // set by Boinc for multi-threaded apps

static vector<string> vs_ExtraParams;

static APP_INIT_DATA aid;          // misc task startup info, not accessible by other means

//
// Abstract application interface
//
class WRAPPER_FUNCTIONS
{
public:
    // Get name of program to run. Function must set 'sMainProgram'.
    // Optionally, extra arguments could be appended to global 'vs_ExtraParams'.
    virtual void get_application_name(string &sMainProgram) = 0;

    // Parse one line of child output.
    // Return true if line should be copied to task stderr, false to hide it (noise or should not be seen by user)
    virtual bool parse_child_stdout_line(char *buf) = 0;

    // Get timestamp (usually st_mtime) of checkpoint file for apps which do checkpointing in background.
    // Return 0 if not supported, unknown, or checkpoint state in unconsistent
    virtual time_t get_checkpoint_timestamp(void) = 0;

    // Task finished. Postprocess result files (check, copy to destination, etc.).
    // 'status' is current error code. Function can set it if fatal error occured
    // and task must be aborted, otherwise it must be kept unchanged.
    virtual void postprocess_results(int &status) = 0;

    // Get trickle name for periodical progress report, or NULL if trickles are not supported
    virtual const char *get_trickle_name(void) { return NULL; }

};

static void send_status_message();
static int  execute_program(string sMainProgram, vector<string> &vs_ExtraParams);
static void execute_cleanup(void);
static bool poll_application(int& status, bool main_program, bool &abnormal_termination);
static void poll_child_stdout(WRAPPER_FUNCTIONS *methods);

//
// Specific application interfaces
//
class SIEVE_FUNCTIONS : public WRAPPER_FUNCTIONS
{
private:
    bool   range_complete;
public:
    void   get_application_name(string &sMainProgram);
    bool   parse_child_stdout_line(char *buf);
    time_t get_checkpoint_timestamp(void);
    void   postprocess_results(int &status);
    SIEVE_FUNCTIONS() : range_complete(false) {}
};

class LLR2_FUNCTIONS : public WRAPPER_FUNCTIONS
{
public:
    void   get_application_name(string &sMainProgram);
    bool   parse_child_stdout_line(char *buf);
    time_t get_checkpoint_timestamp(void);
    void   postprocess_results(int & /* status */) { };
    const char *get_trickle_name(void) { return "llr_progress"; }
};

static SIEVE_FUNCTIONS methods_sieve;
static LLR2_FUNCTIONS  methods_llr2;

static string quote_spaces(string s)
{
    if (s.find(' ') == string::npos)
        return s;
    return "\"" + s + "\"";
}

void SIEVE_FUNCTIONS::get_application_name(string &sMainProgram)
{
    string sInputFile;

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
}

void LLR2_FUNCTIONS::get_application_name(string &sMainProgram)
{
    char buf[128];

    boinc_resolve_filename_s("llr2", sMainProgram);

    vs_ExtraParams.push_back("-d");  // -d is mandatory, even if not sent by server

    if (num_threads)
    {
        sprintf(buf, "-t%u", num_threads);
        vs_ExtraParams.push_back(buf);
    }

    // LLR checkpoint interval
    unsigned cp = aid.checkpoint_period >= 1 ? (unsigned)aid.checkpoint_period : DEFAULT_CHECKPOINT_PERIOD;
    sprintf(buf, "-oDiskWriteTime=%u", (cp + 59) / 60);
    vs_ExtraParams.push_back(buf);


    // Get LLR version first (run "llr -v" and save output)
    vector<string> params;
    int status;

    params.push_back("-v");
    if ((status = execute_program(sMainProgram, params)) == 0)
    {
        for (;;)
        {
            bool terminated, ab;

            terminated = poll_application(status, false, ab);
            poll_child_stdout(this); // even if terminated, get remaining app output
            if (terminated)
                break;
            boinc_sleep(0.1);
        }
        execute_cleanup();
    }
    else
        fprintf(stderr, "can't get LLR version: %d\n", status);
}

static int run_application(WRAPPER_FUNCTIONS *methods)
{
    string sMainProgram;

    methods->get_application_name(sMainProgram);

    return execute_program(sMainProgram, vs_ExtraParams);
}

static int execute_program(string sMainProgram, vector<string> &vs_ExtraParams)
{
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
        fprintf(stderr, "CreateProcess() failed: GetLastError()=0x%08lX\n", (ULONG)GetLastError());
        free(args);
        return ERR_EXEC;
    }
    free(args);
    pid           = process_info.dwProcessId;
    pid_handle    = process_info.hProcess;
    CloseHandle(process_info.hThread);  // not required
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
// Delayed cleanup after child termination.
//
static void execute_cleanup(void)
{
#ifdef _WIN32
        // On Windows, process handle must be closed.
        // Delayed because it's used in get_cpu_time() even after termination.
        CloseHandle(pid_handle);
#endif
}

//
// on error, return false and keep old cpu_time
//
static bool get_child_cpu_time(double& cpu_time)
{
    double t;

    // If child terminated, try to use his final CPU time, if known
    if (final_cpu_time)
    {
        cpu_time = final_cpu_time;
        return true;
    }

#ifdef _WIN32
    // return -1 on error
    if (boinc_process_cpu_time(pid_handle, t) < 0)
        return false;
#elif defined(__linux__)
    // return zero time on error
    t = linux_cpu_time(pid);
    if (t == 0)
        return false;
#elif defined(__APPLE__)
    // There's no easy way to get another process's CPU time in Mac OS X?
    // Report runtime, it's better then nothing.
    t = boinc_elapsed_time();
#else
#error How to get child CPU time for your OS?
#endif
    cpu_time = t;
    return true;
}

//
// If possible, get final CPU time of exited process
// (this is a only way to report true CPU time on Mac)
//
static void get_final_cpu_time()
{
#ifdef _WIN32
    // nothing. no graceful termination anyway
#else
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) < 0)
        perror("getrusage");
    else
    {
        final_cpu_time = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec +
            ((double)ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
#ifdef VERBOSE
        fprintf(stderr, "Final CPU time set to %f\n", final_cpu_time);
#endif
    }
#endif
}

bool SIEVE_FUNCTIONS::parse_child_stdout_line(char *buf)
{
    char *pat;

    if (isdigit(*buf) && strstr(buf, " | ") && strchr(buf, '^')) // factor, like "109037563 | 3*2^41396435-1"
    {
        // ignore it
    }
    // status lines
    // p=11449790522095243, 2198332 p/sec, 0 factors, 99.9% cpu, ETA 03 May 13:45
    // p=11449790260702471, 2197347 p/sec, 0 factors, 2.6% done, ETA 03 May 13:43
    // p=110499161, 1000564 p/sec, 47 factors, 10.5% done, ...
    // p=110499161, 1000564 p/sec, 1 factor, 10.5% done, ...  (ouch...)
    else if (buf[0] == 'p' && buf[1] == '=' && isdigit(buf[2]) &&
             (pat = strstr(buf, "% done, ")) != NULL
            )
    {
        do { --pat; } while (pat != buf && *pat != ' ');  // scan back to the whitespace
        pat++;  // skip whitespace
        ratio_done     = atof(pat) / 100;
        status_updated = true;
#ifdef VERBOSE
        fprintf(stderr, "done: %f\n", ratio_done);
#endif
    }
    else if (buf[0] == 'p' && buf[1] == '=' && isdigit(buf[2]) && strstr(buf, "% cpu, "))
    {
        // status line with CPU usage (see above), ignore it
    }
    else
    {
        // extra postprocessing
        if (strstr(buf, "because range is complete"))
        {
            fprintf(stderr, "Detected range complete\n");
            range_complete = true;
            ratio_done     = 1.0;
            status_updated = true;
        }
        // everything else copied to our stderr log
        return true;
    }
    // hide this line
    return false;
}

bool LLR2_FUNCTIONS::parse_child_stdout_line(char *buf)
{
    // LLR uses spaces to cleanup lines on screen, skip them and ignore such lines
    while (isspace(*buf)) buf++;
    if (*buf == 0) return false;

    // Status line
    // 27*2^785264+1, bit: 580000 / 785263 [73.86%], 537251 checked.  Time per bit: 0.184 ms.
    // Resuming Proth prime test of 27*2^785264+1 at bit 781457 [99.51%]
    bool keep_status = false;
    char *p = strstr(buf, " bit: ");
    if (p == NULL)
    {
        keep_status = true;
        p = strstr(buf, "Resuming ");
    }
    if (p)
    {
        for (; *p; p++)
        {
            if (*p == '[' && (isdigit(p[1]) || p[1] == '.'))
            {
                ratio_done = atof(p+1) / 100;
                status_updated = true;
#ifdef VERBOSE
                fprintf(stderr, "done: %f\n", ratio_done);
#endif
                return keep_status;
            }
        }
    }

    // Hide residues and primes (print own message)
    if ( strstr(buf, "RES64") || strstr(buf, " is prime!") || (strstr(buf, " is ") && strstr(buf, " PRP! ")) )
    {
        fprintf(stderr, "Testing complete.\n");
        ratio_done     = 1.0;
        status_updated = true;
        return false;
    }

    // Strings which are part of prime testing and may reveal a prime
    static const char * const strings[] =
    {
        "(Factorized part = ",
        "Candidate saved in file ",
        NULL
    };
    for (const char * const *p = strings; *p; p++)
    {
        if (strstr(buf, *p) == buf)
            return false;
    }

    return true;
}

static void poll_child_stdout(WRAPPER_FUNCTIONS *methods)
{
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
            // got complete line
            *end = 0;
            // parse line contents
            if (*buf == 0)
            {
                // empty line, ignored
            }
            else if (methods->parse_child_stdout_line(buf))
            {
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
#ifdef _WIN32
        if (hChildStdoutRd == INVALID_HANDLE_VALUE)
            break;
        DWORD gotBytes = 0;
        if (!PeekNamedPipe(hChildStdoutRd, NULL, 0, NULL, &gotBytes, NULL))
        {
            CloseHandle(hChildStdoutRd); // child process terminated, do not leak handle
            hChildStdoutRd = INVALID_HANDLE_VALUE;
            break;
        }
        if (!gotBytes) // no data available
            break;
        if (!ReadFile(hChildStdoutRd, buf + len, sizeof(buf)-len-1, &gotBytes, NULL))
        {
            fprintf(stderr, "pipe ReadFile(): error 0x%lx\n", GetLastError());
            CloseHandle(hChildStdoutRd);
            hChildStdoutRd = INVALID_HANDLE_VALUE;
            break;
        }
        len += gotBytes;
#else
        if (hChildStdoutRd < 0)
            break;
        ssize_t gotBytes;
        gotBytes = read(hChildStdoutRd, buf + len, sizeof(buf)-len-1);
        if (gotBytes == 0)  // child terminated - do not leak handle
        {
            close(hChildStdoutRd);
            hChildStdoutRd = -1;
        }
        else if (gotBytes < 0)   // error
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)  // really, no data yet
                gotBytes = 0;
            else
            {
                perror("pipe read");
                close(hChildStdoutRd);
                hChildStdoutRd = -1;
            }
        }
        if (gotBytes <= 0)  // error or no data available
            break;
        len += gotBytes;
#endif
        // back to parsing loop
    }
}

// Get timestamp (usually st_mtime) of checkpoint file for apps which do checkpointing in background.
// Return 0 if not supported, unknown, or checkpoint state in unconsistent
time_t SIEVE_FUNCTIONS::get_checkpoint_timestamp(void)
{
    struct stat st;
    static const char file[] = "checkpoint.txt";

    return (stat(file, &st) == 0 && st.st_size != 0) ? st.st_mtime : 0;
}

time_t LLR2_FUNCTIONS::get_checkpoint_timestamp(void)
{
    struct stat st;
    static const char *ckpt_file;

    // LLR checkpoints have random names like z123457 ( /^z\d+$/ )
    // Find suitable file first
    if (ckpt_file == NULL)
    {
        DIRREF dir = dir_open(".");
        if (dir)
        {
            char file[512];
            while (dir_scan(file, dir, sizeof(file)) == 0)
            {
                if ((file[0] == 'z' || file[0] == 'Z') && file[1])
                {
                    for (char *p = file+1; ; p++)
                    {
                        if (*p == 0)  // successfully reached end of string, only digits detected
                        {
                            ckpt_file = strdup(file);
#ifdef VERBOSE
                            fprintf(stderr, "checkpoint name set to '%s'\n", file);
#endif
                        }
                        if (!isdigit(*p))
                            break;
                    }
                }
            }
            dir_close(dir);
        }
    }

    return (ckpt_file && stat(ckpt_file, &st) == 0 && st.st_size != 0) ? st.st_mtime : 0;
}

// Since app does checkpointing in background, monitor modification time
// of checkpoint file. On change, assume that app has checkpointed.
static void poll_checkpoint_file(WRAPPER_FUNCTIONS *methods, bool report)
{
    static time_t last_time;
    time_t mtime;

    if ((mtime = methods->get_checkpoint_timestamp()) != 0 && mtime != last_time)
    {
        last_time = mtime;
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

static bool poll_application_exit(int& status, bool& abnormal)
{
    abnormal = false;
#ifdef _WIN32
    DWORD exit_code;
    if (GetExitCodeProcess(pid_handle, &exit_code))
    {
        if (exit_code == STILL_ACTIVE)
            return false;
        if ((exit_code & 0xC0000000) == 0xC0000000)  // try to catch exceptions / GPF / system shutdown
            abnormal = true;
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
        if (WIFEXITED(stat))
            status = WEXITSTATUS(stat);
        else
        {
            abnormal = true;
            status   = 0;
            if (WIFSIGNALED(stat))
                fprintf(stderr, "Application terminated by signal %d\n", WTERMSIG(stat));
            else
                fprintf(stderr, "Application terminated by unknown reason\n");
        }
        return true;
    }
#endif
    // Cannot get status. May be do something here.
    return false;
}

static bool poll_application(int& status, bool main_program, bool& abnormal_termination)
{
    int exit_code;

    if (poll_application_exit(exit_code, abnormal_termination))
    {
        if (main_program)
            get_final_cpu_time();
        if (exit_code)
        {
            fprintf(stderr, "Application terminated with exit code %d (0x%08X)\n", exit_code, exit_code);
            status = EXIT_CHILD_FAILED;
        }
        return true;
    }
    return false;
}

//
// A "Suspening" / "Resuming" pair can produce LOT of output if user selected short
// inactivity period. Print only few such messages, then block them for a while.
//
static void noisy_message(const char *message)
{
    static time_t suspend_until;
    static int count;

    if (suspend_until)
    {
        if (time(NULL) < suspend_until)
            return;
        suspend_until = 0;
    }
    fputs(message, stderr);
    if (++count == 6)
    {
        fputs("Suspending noisy messages for 4 hours\n", stderr);
        suspend_until = time(NULL) + 3600*4;
        count = 0;
    }
}

static void resume_app()
{
    noisy_message("Resuming\n");
    suspend_or_resume_process(pid, true);
}

static void stop_app()
{
    noisy_message("Suspending\n");
    suspend_or_resume_process(pid, false);
}

// kill this task (gracefully if possible) and any other subprocesses
// Linux Boinc lib sends SIGTERM, it's OK for sr2sieve
static void kill_app(WRAPPER_FUNCTIONS *methods)
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

    get_final_cpu_time();  // get final CPU time of terminated app
    poll_child_stdout(methods);   // get remaining messages for logging
    poll_checkpoint_file(methods, true);
    send_status_message(); // if app checkpointed on exit, send new info

    // sr2sieve bug: no output after signal if stdout is redirected, only console works.
    // easy to confirm with 'sr2sieve ... >file' and Ctrl-C
}

// MUST kill app gracefully for correct shutdown and checkpointing
// For sr2sieve, it's OK to use kill_app() (SIGTERM)
static void terminate_app(WRAPPER_FUNCTIONS *methods)
{
    kill_app(methods);
}

static void poll_boinc_messages(WRAPPER_FUNCTIONS *methods)
{
    BOINC_STATUS status;
    boinc_get_status(&status);
    if (status.no_heartbeat)
    {
        fprintf(stderr, "Terminating - no heartbeat\n");
        terminate_app(methods);
        exit(0);
    }
    if (status.quit_request)
    {
        fprintf(stderr, "Terminating - quit request\n");
        terminate_app(methods);
        exit(0);
    }
    if (status.abort_request)
    {
        fprintf(stderr, "Terminating - abort request\n");
        kill_app(methods);
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

#define TRICKLE_PERIOD             (24 * 3600)   // Send trickles each 24 hours
#define TRICKLE_FIRST_REPORT_DELAY (10 * 60)     // Send first trickle if task is running more then 10 minutes

static const char trickle_file[] = "trickle_ts.txt";

static void save_trickle_file(time_t ts)
{
    FILE *f = fopen(trickle_file, "wt");
    if (f)
    {
        fprintf(f, "%ld\n", (long)ts);
        fclose(f);
    }
}

static void send_trickle_message(WRAPPER_FUNCTIONS *methods)
{
    static time_t last_trickle_time;
    const char *variety = methods->get_trickle_name();

    if (variety == NULL) return;

    time_t now = time(NULL);

    // On first run, try to load saved timestamp of last trickle
    if (last_trickle_time == 0)
    {
        FILE *f = fopen(trickle_file, "rt");
        if (f)
        {
            long tmp;
            if (fscanf(f, "%ld", &tmp) == 1)
                last_trickle_time = tmp;
            fclose(f);
        }
        // If no trickles were sent yet, schedule it to be sent few minutes after start
        // (to be sure that task started up just fine). Otherwise, if Boinc starts a
        // task too close to deadline and did't finish it in time (wrong completion estimate
        // or paused by user), server will be not aware that task is running and will
        // resend potentially good task.
        if (last_trickle_time == 0)
        {
            last_trickle_time = now - TRICKLE_PERIOD + TRICKLE_FIRST_REPORT_DELAY;
            save_trickle_file(last_trickle_time);
        }
    }

    // Time to send new trickle?
    if (now - last_trickle_time >= TRICKLE_PERIOD && ratio_done >= 0)
    {
        char buf[512];
        static double session_cpu_time;  // keep old time on error

        get_child_cpu_time(session_cpu_time);  // unchanged on error
        snprintf(buf, sizeof(buf),
            "<trickle_up>\n"
            "   <progress>%f</progress>\n"
            "   <cputime>%f</cputime>\n"
            "   <runtime>%f</runtime>\n"
            "</trickle_up>\n",
            ratio_done,
            initial_cpu_time + session_cpu_time,
            aid.starting_elapsed_time + boinc_elapsed_time()
        );
        boinc_send_trickle_up((char *)variety, buf);

        last_trickle_time = now;
        save_trickle_file(last_trickle_time);
    }
}

void SIEVE_FUNCTIONS::postprocess_results(int &status)
{
    int retval;

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
}


//
// Poor man's getopt()
//
static bool parse_cmdline(int argc, char **argv, WRAPPER_FUNCTIONS * &methods)
{
    static const char optstring[] = "?hc:t:";
    static const char * const longopts[] =
    {
        "--llr2",
        "-:nthreads",  // with argument
        NULL
    };
    int i;

    for (i = 1; i < argc; i++)
    {
        char *opt = argv[i];
        const char *idx;
        unsigned optchar;
        char *optarg = NULL;

        // Long option have opcode starting from 256.
        if (opt[0] == '-' && opt[1] == '-')
        {
            // idx[1] points to ':', if option requires an argument
            for (optchar = 0; (idx = longopts[optchar]) != NULL; optchar++)
            {
                if (!strcmp(idx+2, opt+2))
                {
                    optchar += 256;
                    goto have_option;
                }
            }
        }

        if (opt[0] != '-' || (idx = strchr(optstring, (optchar = opt[1]))) == NULL || opt[2] != 0)
        {
            fprintf(stderr, "Unknown option '%s'. Use '-h' for help\n", opt);
            return false;
        }

have_option:
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
            "--llr2         -- llr2 mode (default: srsieve)\n"
            "--nthreads N   -- number of threads for multi-threaded apps (llr2)\n"
            "\n"
            "-t N           -- same as --nthreads\n"
            "-c <text>      -- extra command line parameters for main program\n"
            "                  (may be repeated)\n"
            "\n"
            ;

        switch (optchar)
        {
        case 'c':
            vs_ExtraParams.push_back(optarg);
            break;
        case 't': case 257: // --nthreads
            num_threads = atoi(optarg);
            break;
        case 256:  // --llr2
            methods = &methods_llr2;
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

    WRAPPER_FUNCTIONS *methods = &methods_sieve;

#ifndef _WIN32
    // Close good amount of possibly opened (inherited) handles except standard 0-2
    // (stdin, stdout, stderr) to avoid handle-inheritance-on-exec bug in older Boinc clients
    // https://github.com/BOINC/boinc/issues/1388
    for (int i = 3; i < 100; i++)
        close(i);
#endif

    boinc_init_diagnostics(
        BOINC_DIAG_DUMPCALLSTACKENABLED |
        BOINC_DIAG_HEAPCHECKENABLED |
        BOINC_DIAG_TRACETOSTDERR |
        BOINC_DIAG_REDIRECTSTDERR
    );

    fprintf(stderr, "BOINC PrimeGrid wrapper 2.01 (" __DATE__ " " __TIME__ ")\n");

    memset(&options, 0, sizeof(options));
    options.main_program = true;
    options.check_heartbeat = true;
    options.handle_process_control = true;
#if API_VERSION < 70500   /* Didn't tested myself, but at least 7.11 really have no such field */
    options.handle_trickle_ups = true;
#endif
    boinc_init_options(&options);

    // get a copy of full Boinc startup data
    boinc_get_init_data(aid);

    if (parse_cmdline(argc, argv, methods) == false)
        boinc_finish(EXIT_INIT_FAILURE);

    // Workaround for "finish file present too long" problem
    if (!boinc_is_standalone() && boinc_file_exists("boinc_finish_called"))
    {
        fprintf(stderr, "The job is already completed\n");
        exit(0);  // standard exit. boinc_finish was already done early
    }

    // get CPU time spent in previous sessions (really, until checkpoint from which we'll continue)
    boinc_wu_cpu_time(initial_cpu_time);
    // get initial timestamp of checkpoint file, if exist
    poll_checkpoint_file(methods, false);

    int status;

    status = run_application(methods);
    if (status)
    {
        fprintf(stderr, "can't run app: %d\n", status);
        boinc_finish(status);
    }

    // Main monitoring loop

    bool abnormal_termination;
    for (;;)
    {
        bool terminated;

        terminated = poll_application(status, true, abnormal_termination);

        // even if terminated, get remaining app output and send message with final CPU time
        poll_child_stdout(methods);
        poll_checkpoint_file(methods, true);
        send_status_message();

        if (terminated)
            break;

        // finally, process control messages from client
        poll_boinc_messages(methods);
        send_trickle_message(methods);
        boinc_sleep(1.);
    }
    execute_cleanup();

    // If application crashed or killed, attempt to restart it

    if (abnormal_termination)
        boinc_temporary_exit(5, "Attempting to restart failed application");

    // Postprocess results

    methods->postprocess_results(status);

    // Done
    boinc_finish(status);
    return status;
}
