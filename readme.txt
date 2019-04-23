
Boinc sieve (sr2sieve and similar) wrapper.

Setting up a task
=================

1) Old style (can be used as drop-in replacement for old wrapper).
Boinc will prepare following symlinks (all of them are optional for wrapper):

   a) "cmd" => copied as "sr2sieve-command-line.txt" (magic name for sr2sieve);
   b) "in"  => copied as "input.txt" (this name is hardcoded in sr2sieve-command-line.txt)

   Note: it was design error, correct task template should be written instead - Boinc
client could copy these files under necessary names himself.

   c) executes one of following (usually, it's symlink pointing to real executable):
      "primegrid_sr2sieve_1.*"
      "primegrid_pps_sr2sieve_1.*"
      "primegrid_psp_sr2sieve_1.*"

   This should make wrapper compatible with old tasks of all projects.


2) New style (recommended for new projects and tasks)

   a) Use wrapper command-line option "-c" to pass any number of arguments
      to sieving program. This option could be repeated unlimited, all arguments
      are joined together. For example, following two wrapper command lines have
      same effect, although second one looks a bit weird:

       -c "-p 1e8 -P 2e8 -S 30"
       -c -p -c 1e8 -c "-P 2e8" -c -S -c 30

   b) if a symlink "in_v2" exist, wrapper automatically appends option "-i <file>" to the
      command line of sieving program, pointing to necessary input sieve.

   c) executes a program specified in "sieve_program" symlink.


Logging
=======

Wrapper now logs all output of sieving program to the own "stderr.txt", with exception
of few noisy messages (status and factors).


Reporting progress
==================

The percentage done is reported to Boinc when it's detected and fetched from sr2sieve status
output. It happens at least every 60 seconds.


Case of no factors found
========================

Fake factor file ("no factors") is written only when wrapper detects a sr2sieve message about
successful completion of the range:

   "... stopped: ... because range is complete."

(exact trigger is "because range is complete").

Also, since complete sr2sieve output is available in stderr output, additional processing
could be implemented in validator.
