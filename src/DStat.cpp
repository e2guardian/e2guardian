// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <sys/stat.h>

#include "DStat.hpp"
#include "Logger.hpp"
#include "OptionContainer.hpp"

// GLOBALS
extern OptionContainer o;

DStat dstat;


void DStat::clear()
{
    conx = 0;
    reqs = 0;
};

void DStat::start()
{
    clear();
    start_int = time(NULL);
    end_int = start_int + o.dstat.dstat_interval;
    if (o.dstat.dstat_log_flag) {
        o.proc.become_root_user();
        mode_t old_umask;
        old_umask = umask(S_IWGRP | S_IWOTH);
        fs = fopen(o.dstat.dstat_location.c_str(), "a");
        if (fs) {
    	    if (o.dstat.stats_human_readable){
            fprintf(fs, "time		        httpw	busy	httpwQ	logQ	conx	conx/s	 reqs	reqs/s	maxfd	LCcnt\n");
	        } else {
            fprintf(fs, "time		httpw	busy	httpwQ	logQ	conx	conx/s	reqs	reqs/s	maxfd	LCcnt\n");
	        }
        } else {
          e2logger_error("Unable to open dstats_log '", o.dstat.dstat_location, "' for writing. Continuing without logging");
          o.dstat.dstat_log_flag = false;
        };
        maxusedfd = 0;
        fflush(fs);
        umask(old_umask);
        o.proc.become_root_user();
    };
};

void DStat::reset()
{    
    time_t now = time(NULL);
    int bc = busychildrens;
    long period = now - start_int;
    long cnx = (long)conx;
    long rqx = (long) reqs;
    int mfd = maxusedfd;
    int LC = o.LC_cnt;

    // clear and reset stats now so that stats are less likely to be missed
    clear();

    if (!fs) return; //file is NOT open !

    if ((end_int + o.dstat.dstat_interval) > now)
        start_int = end_int;
    else
        start_int = now;

    end_int = start_int + o.dstat.dstat_interval;

    long cps = cnx / period;
    long rqs = rqx / period;

    if (o.dstat.stats_human_readable){
        struct tm * timeinfo;
        time(&now);
        timeinfo = localtime ( &now );
        char buffer [50];
        strftime (buffer,50,"%Y-%m-%d %H:%M",timeinfo);
    	fprintf(fs, "%s	%d	%d	%d	%d	%ld	%ld	%ld	 %ld	%d	 %d\n", buffer, o.http_workers,
                    bc, o.http_worker_Q.size(), o.log.log_Q.size(), cnx, cps, rqx, rqs, mfd, LC);
    } else {
        fprintf(fs, "%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld	%d	%d\n", now, o.http_workers,
                    bc, o.http_worker_Q.size(), o.log.log_Q.size(), cnx, cps, rqx, rqs, mfd, LC);
    }

    fflush(fs);
};

void DStat::close()
{
    if (fs != NULL) fclose(fs);
};

void DStat::timetick(){
    time_t now = time(NULL);
    if  (now >= end_int)
        reset();
}
