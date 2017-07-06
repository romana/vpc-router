# Deploying vpc-router in production

## Installation via setup.py

After downloading the code, run the `setup.py` script, which performs a proper
install and puts vpcrouter in your path:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ cd vpc-router
    $ python setup.py install
    $ vpcrouter .......

## Running on an EC2 instance in the VPC

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

