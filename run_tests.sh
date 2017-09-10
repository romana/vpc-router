#!/bin/bash

# Run unit tests and create a coverage report.
#
# To run the test suite for the entire package, don't specify any options:
#
#    $ ./run_tests.sh
#
# To run specific tests, specify those as command line option:
#
#    $ ./run_tests.sh vpcrouter.tests.test_vpc.TestVpcUtil vpcrouter.tests.test_utils

rm .coverage*    # cover-erase with multiprocessing seemed to cause issues
                 # (warning messages or some lines not shown as covered)
                 # so deleting old cover files manually instead

nosetests -v --config=nose.cfg $@

echo "@@@ Coverage report: file:///tmp/vpc-router-coverage/index.html"
echo
