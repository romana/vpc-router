"""
Copyright 2017 Pani Networks Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

#
# Functions for monitoring instances
#

import logging
import ping
import Queue
import socket
import threading
import time


class _StopReceived(Exception):
    """
    Raised after monitor thread receives stop signal.

    """
    pass


def my_do_one(dest_addr, ping_id, timeout, psize):
    """
    Returns either the delay (in seconds) or none on timeout.

    This is a copy of the do_one function in the ping packet, but importantly,
    the ID for the ping packet is different (it's now passed in from the
    caller). Originally, the PID was used, which is not thread safe.

    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise  # raise the original error

    ping.send_one_ping(my_socket, dest_addr, ping_id, psize)
    delay = ping.receive_one_ping(my_socket, ping_id, timeout)

    my_socket.close()
    return delay


def _do_ping(ip, ping_id, results):
    """
    Send a single ping to a specified IP address.

    The result is either a time in seconds for the ping, or None if no result
    was received from the pinged IP address in time. Store the result in the
    results dict that's provided to us.

    """
    try:
        res = my_do_one(ip, ping_id, 2, 16)
    except Exception:
        # If an unreachable name or IP is specified then we might even get an
        # exception here. Still just return None in that case.
        res = None
    results[ip] = res


def _get_new_working_set(q_monitor_ips):
    """
    Get a new list of IPs to work with from the queue.

    This returns None if there is no update.

    Read all the messages from the queue on which we get the IP addresses
    that we have to monitor. We will ignore all of them, except the last
    one, since maybe we received two updates in a row, but each update
    is a full state, so only the last one matters.

    Raises the _StopReceived exception if the stop signal ("None") was received
    on the notification queue.

    """
    new_list_of_ips = None
    while True:
        try:
            new_list_of_ips = q_monitor_ips.get_nowait()
            q_monitor_ips.task_done()
            if new_list_of_ips is None:
                raise _StopReceived()
        except Queue.Empty:
            # No more messages, all done reading monitor list for now
            break
    return new_list_of_ips


def _do_health_checks(list_of_ips):
    """
    Perform a health check on a list of IP addresses.

    Each check (we use ICMP echo right now) is run in its own thread.

    Gather up the results and return the list of those addresses that failed
    the test.

    TODO: Currently, this starts a thread for every single address we want to
    check. That's probably not a good idea if we have thousands of addresses.
    Therefore, we should implement some batching for large sets.

    """
    threads = []
    results = {}

    # Start the thread for each IP we wish to ping.
    # We calculate a unique ID for the ICMP echo request sent by each thread.
    # It's based on the slowly increasing time stamp (just 8 bits worth of the
    # seconds since epoch)...
    nowsecs = int(time.time()) % 255
    for count, ip in enumerate(list_of_ips):
        ping_id = (nowsecs << 8) + count  # ... plus running count of packets
        thread = threading.Thread(target=_do_ping,
                                  args=(ip, ping_id, results))
        thread.start()
        threads.append(thread)

    # ... make sure all threads are done...
    for thread in threads:
        thread.join()

    # ... and gather up the results and send back if needed
    return [k for (k, v) in results.items() if v is None]


def start_monitoring(q_monitor_ips, q_failed_ips, interval=2):
    """
    Monitor IP addresses and send notifications if one of them has failed.

    This function will continuously monitor q_monitor_ips for new lists of IP
    addresses to monitor. Each message received there is the full state (the
    complete lists of addresses to monitor).

    Push out (return) any failed IPs on q_failed_ips. This is also a list of
    IPs, which may be empty if all instances work correctly.

    If q_monitor_ips receives a 'None' instead of list then this is intepreted
    as a stop signal and the function exits.

    """
    time.sleep(1)
    logging.debug("Started health monitoring thread")

    # This is our working set. This list may be updated occasionally when we
    # receive messages on the q_monitor_ips queue. But irrespective of any
    # received updates, the list of IPs in here is regularly checked.
    list_of_ips             = []
    currently_failed_ips    = set()

    # Accumulating failed IPs for 10 intervals before rechecking them to see if
    # they are alive again
    recheck_failed_interval = 10

    try:
        interval_count = 0
        while True:
            # See if we should update our working set
            new_ips = _get_new_working_set(q_monitor_ips)
            if new_ips:
                list_of_ips = new_ips

            # Don't check failed IPs for liveness on every interval. We
            # keep a list of currently-failed IPs for that purpose.
            live_ips_to_check = [ip for ip in list_of_ips if
                                 ip not in currently_failed_ips]
            logging.debug("Checking live IPs: %s" %
                          (",".join(live_ips_to_check) if live_ips_to_check
                                                       else "(none alive)"))

            # Independent of any updates: Perform health check on all IPs in
            # the working set and send messages out about any failed once as
            # necessary.
            if live_ips_to_check:
                failed_ips = _do_health_checks(live_ips_to_check)
                if failed_ips:
                    q_failed_ips.put(failed_ips)
                    # Update list of currently failed IPs with any new ones
                    currently_failed_ips.update(failed_ips)
                    logging.info('Currently failed IPs: %s' %
                                 ",".join(currently_failed_ips))

            if interval_count == recheck_failed_interval:
                # Ever now and then clean out our currently failed IP cache so
                # that we can recheck them to see if they are still failed.
                interval_count = 0
                currently_failed_ips = set()

            time.sleep(interval)
            interval_count += 1

    except _StopReceived:
        # Received the stop signal, just exiting the thread function
        return


def start_monitor_thread(interval=2):
    """
    Start a thread for the monitor function.

    Specify the interval in seconds: Time between health checks of the
    specified IP addresses.

    This function returns a 3-tuple consisting of the monitoring thread, the
    monitor-queue and the failed-ips-queue.

    The monitor-queue is used to pass in sets of IPs for regular monitoring. A
    new message here needs to consists of the complete set of IPs that should
    be monitored.

    The failed-ips-queue is used by the monitoring thread to communicate back
    any failed IPs it has discovered. It's up to whoever listens on this queue
    ot then take actions.

    """
    # Prepare two queues for communication with the thread
    q_monitor_ips  = Queue.Queue()
    q_failed_ips   = Queue.Queue()
    monitor_thread = threading.Thread(target = start_monitoring,
                                      name   = "HealthMon",
                                      args   = (q_monitor_ips, q_failed_ips,
                                                interval))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Return the thread and the two queues to the caller
    return (monitor_thread, q_monitor_ips, q_failed_ips)
