# S3 Bucket Management and Monitoring Project

This project uses Terraform to set up and manage multiple S3 buckets with various security configurations, CloudTrail logging, and replication. It also includes CloudWatch monitoring for replication failures.

## Project Components

1. S3 Buckets:
    - Bucket 1: Public read access for static website hosting
    - Bucket 2: Private access for confidential company documents
    - Bucket 3: Limited access for specific IAM roles for data analytics
    - Logging Bucket: For storing access logs and CloudTrail logs

2. CloudTrail:
    - Monitors data events for Bucket 2 and Bucket 3
    - Logs stored in the Logging Bucket and CloudWatch Logs

3. S3 Replication:
    - Cross-region replication for Bucket 2
    - Replication metrics and failure monitoring

4. CloudWatch:
    - Metric alarm for replication failures
    - SNS topic for alerting