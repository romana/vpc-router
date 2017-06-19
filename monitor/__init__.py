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

import ping
import Queue
import time
import threading


class StopReceived(Exception):
    pass


def _do_ping(ip, results):
    """
    Send a single ping to a specified IP address.

    The result is either a time in seconds for the ping, or None if no result
    was received from the pinged IP address in time. Store the result in the
    results dict that's provided to us.

    """
    try:
        res = ping.do_one(ip, 2, 1)
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

    Raises the StopReceived exception if the stop signal ("None") was received
    on the notification queue.

    """
    new_list_of_ips = None
    while True:
        try:
            new_list_of_ips = q_monitor_ips.get_nowait()
            q_monitor_ips.task_done()
            if new_list_of_ips is None:
                raise StopReceived()
        except Queue.Empty:
            # No more messages, all done reading monitor list for now
            break
    return new_list_of_ips



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
    # This is our working set. This list may be updated occasionally when we
    # receive messages on the q_monitor_ips queue. But irrespective of any
    # received updates, the list of IPs in here is regularly checked.
    list_of_ips = []
    try:
        while True:
            # See if we should update our working set
            new_ips = _get_new_working_set(q_monitor_ips)
            if new_ips:
                list_of_ips = new_ips

            # Start a thread for each IP address to check if it's available.
            if list_of_ips:
                threads = []
                results = {}
                # Start the thread for each IP we wish to ping...
                for ip in list_of_ips:
                    thread = threading.Thread(target=_do_ping,
                                              args=(ip, results))
                    thread.start()
                    threads.append(thread)
                # ... make sure all threads are done...
                for thread in threads:
                    thread.join()
                # ... and gather up the results and send back if needed
                failed_ips = [ k for k,v in results.items() if v is None ]
                if failed_ips:
                    q_failed_ips.put(failed_ips)

            time.sleep(interval)
    except StopReceived:
        # Received the stop signal, just exiting the thread function
        return


def start_monitor_in_background(interval=2):
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
    monitor_thread = threading.Thread(target=start_monitoring,
                                      args=(q_monitor_ips, q_failed_ips,
                                            interval))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Return the thread and the two queues to the caller
    return (monitor_thread, q_monitor_ips, q_failed_ips)

