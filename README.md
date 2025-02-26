# Cloudflare Security Group Sync

[![Version](https://img.shields.io/badge/version-v1.0.0-blue.svg)](https://github.com/Jfami/AWS_Cloudflare_SecurityGroups/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-green.svg)](LICENSE)

Synchronize your AWS Security Groups (ports 80 and 443) with the latest IP ranges published by [Cloudflare](https://www.cloudflare.com/). This ensures that only traffic routed through Cloudflare can reach your servers on those ports, preventing direct access from arbitrary IPs.

## 📋 About

**Author:** Jordi Fuerte Amill  
**LinkedIn:** [https://www.linkedin.com/in/jfamill/](https://www.linkedin.com/in/jfamill/)  
**GitHub:** [https://github.com/Jfami](https://github.com/Jfami)  
**License:** BSD 3-Clause  
**Repository:** [https://github.com/Jfami/AWS_Cloudflare_SecurityGroups](https://github.com/Jfami/AWS_Cloudflare_SecurityGroups)

## ✨ Features

- **🔄 Sync:** Compares current SG rules against the official Cloudflare IP list
- **🚫 Revokes:** IPs that no longer appear in Cloudflare's list
- **✅ Authorizes:** new IPs added by Cloudflare
- **🔒 Ports 80/443 Only:** Leaves other ports (e.g., SSH) untouched
- **🌐 IPv4 + IPv6:** Full support for both address types

## 🚀 Usage

### 1. AWS Lambda Setup

1. Create an AWS Lambda function (e.g., `Python 3.9`)
2. Copy/paste the `sync_cf_sg.py` code into the function
3. Make sure you give your Lambda an IAM Role with permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:DescribeSecurityGroups",
           "ec2:AuthorizeSecurityGroupIngress",
           "ec2:RevokeSecurityGroupIngress"
         ],
         "Resource": "*"
       }
     ]
   }
   ```
4. Adjust REGION and SGS within the script to match your AWS environment
5. Set a Lambda timeout of at least 10 seconds

### 2. Manual Test

- Configure a test event (empty JSON) and hit Test
- Check CloudWatch Logs to see if obsolete IPs were revoked and new IPs added

### 3. Scheduling

- Optionally create an EventBridge (CloudWatch Events) rule to run the Lambda periodically (e.g., cron(0 * * * ? *) for hourly updates)
- The script will keep the Security Groups up-to-date with Cloudflare's IP changes

## 📝 Notes

- This script specifically manages inbound rules on ports 80/443 only
- If you need additional ports, expand the logic accordingly
- If Cloudflare publishes more IPs than a single SG rule can hold (approaching AWS limits), consider segmenting them or using an AWS WAF + ALB approach

## 📜 License

This project is licensed under the BSD 3-Clause License.
Feel free to use, modify, and distribute, but please mention the original author.