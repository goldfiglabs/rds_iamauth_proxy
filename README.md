rds-proxy
=========

`rds-proxy` lets you make use of IAM-based authentication to
AWS RDS instances from tools that don't natively support
that method of authentication.

To use it, set up a config file to point to the desired RDS Instance.
When you run the proxy, it uses the standard methods of picking up an
AWS credential (e.g. credentials file, environment variables, etc.).

Optionally, you can point the proxy at a different endpoint to make use
of something like an SSH tunnel to a bastion host.