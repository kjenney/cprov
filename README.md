# prov

A CLI tool for provisoning cloud resoruces with Pulumi Automation

## Installation

    pip install .

## AWS Backend Configuration

We're using AWS S3 as our backend. The state bucket and KMS key are secret and are stored in a flat file in the root of the repo.

Create `.env` with the following structure:

```
STATE_BUCKET=
KMS_KEY=
```

## Usage

    prov - show help 

## Steps

1) Create VPC
2) Stand up EKS cluster
3) Create application
4) Create DNS record for application


