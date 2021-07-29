# AWS_Subdomain_Takeover_Detector

# Purpose

The purpose of this automation is to detect misconfigured Route53 entries which are vulnerable to subdomain takeover.

# Deployment Options

* AWS Lambda, Rundeck or any cron

# Prerequisites

* IAM role with a permission of route53("ListHostedZones", "ListResourceRecordSets", "ListDomains").

# Configuration Steps

* Configure IAM role with permission mention above in prerequisites.
* Deploy it on any of the cron Lambda/rundeck.
* In slack_alert() please put the incoming webhook url of slack channel.

# Scans Amazon Route53 to identify:
* Check alias records for CloudFront distributions with missing S3 origin, ElasticBeanstalk vulnerable aliaa record and S3 vulnerable Alias record.
* Check CNAME records for CloudFront distributions with missing S3 origin, S3 vulnerable CNAME and ElasticBeanstalk vulnerable CNAME.
* Check for NS subdomain takeover.

# TODO
* Slack Integration ---------> Done
* Detect Elastic ip Takeover





