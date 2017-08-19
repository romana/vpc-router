# Deploying vpc-router in production

## Installing and running the code

### Option 1: Installation via pip

This is the simplest way to install vpc-router:

    pip install vpcrouter

### Option 2: Installation via setup.py

After downloading the code, run the `setup.py` script, which performs a proper
install and puts vpcrouter in your path:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ cd vpc-router
    $ python setup.py install
    $ vpcrouter .......

### Option 3: Running in a container

Pre-built containers for the vpc-router are provided on Quay.io. You can
download the latest version:

    $ docker pull quay.io/romana/vpcrouter

If you prefer to build your own container, a [Dockerfile](Dockerfile) has been
provided with the software. To build your own container, use:

    $ docker build -t yourname/vpcrouter:1.3.2 .

A few command line arguments are set by default in the container, while
others still need to be specified when you run the container. Specifically, the
mode as well as any parameters this mode may require.

For example, to use the configfile mode, run the container with these options,
which provide a mapping for the directory containing the config file:

    $ docker run -v <host-dir-with-conf-file>:/conf \
         quay.io/romana/vpcrouter -m configfile -f /conf/<conffile-name>

To run it in HTTP mode, use the following, which exposes the port 33289 on
which vpc-router listens for requests. Also, a different listen address needs
to be specified:

    $ docker run -p 33289:33289 quay.io/romana/vpcrouter -m http -a 0.0.0.0

Note that in the container, vpc-router logs to stdout, which tends to be the
preferred log destination in containerized environments.


## Running on an EC2 instance in the VPC

Note: The following information is independent of how vpc-router is installed
or run.

### IAM policies

The most common mode of operation is to run vpc-router on an EC2 instance
within the VPC for which routing tables need to be controlled. This has the
advantage that it can auto-detect the AWS region and VPC (the `-r` and `-v`
parameters). It also means that typically it has access to the various
instances for health check purposes.

To modify VPC routes, it requires permissions to access the AWS APIs.
Typically this is done by assigning IAM roles to the instance(s) on which it
runs. A suitable IAM policy for the vpc-router may look like this:

    {
        "Statement": [
            {
                "Action": [
                    "ec2:*Vpc*",
                    "ec2:*Route*",
                    "ec2:Describe*"
                ],
                "Resource": [
                    "*"
                ],
                "Effect": "Allow"
            }
        ]
    }

### Security rules for health checks

In its current form, vpc-router by default performs active health checks on all
the instances listed in the route spec, by sending ICMP Echo ("ping") requests
at regular intervals (`--health icmpecho` option). Please make sure that your
security rules allow for ICMP Echo requests and responses to be exchanged.

If you use different health monitoring plugins, please adjust your security
rules accordingly. For example for the 'tcp' plugin (`--health tcp` option),
please make sure you open the port to which it attempts to connect
(`--tcp_check_port` option).

If you use the multi plugin (`--health multi`) the security rules need to be
configured so that all specified sub plugins (`--multi_plugins ...` option)
can perform their security checks.
