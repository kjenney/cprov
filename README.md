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
    prov up - create the s3 bucket
    prov down - destroy the s3 bucket
    prov preview - preview the changes



