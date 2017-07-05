
## Installation of required dependencies

When developing or contributing to vpc-router it is helpful to install some
useful packages for running local unit tests. You can do so with this command:

    $ pip install -r requirements/develop.txt


## Running out of the source tree

Use the `vpcrouter-runner.py` script to run the program without having to
actually install the application.

    $ ./vpcrouter-runner.py ...


## Testing

To run all unit tests, use the `run_tests.sh` script, like so:

    $ ./run_tests.sh


This also creates code coverage reports in HTML, which are by default stored in
`/tmp/vpc-router-coverage`.


To just run specific tests, use (for example):

    $ python -m unittest vpcrouter.tests.test_utils


Use the `style_test.sh` script to check some common pep8 style guides and
code complexity.

    $ ./style_test.sh


