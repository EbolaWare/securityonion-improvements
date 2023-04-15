# Security Onion Improvements
A collection of enhancements developed to optimize a Security Onion cluster for large-scale enterprise environments.

## 1. Log Scrubber Script (`./log-scrubber.sh`)
This script enables configuration of log retention policies, including maximum and minimum log retention, using SaltStack's Pillar. It currently supports only Zeek logs, as these were the primary logs causing issues in our deployment. 

**Related Issue:** [SecurityOnion Issue #7774](https://github.com/Security-Onion-Solutions/securityonion/issues/7774)

### Deployment Instructions
1. Add the script to your Security Onion deployment.
2. Configure alternate settings in your `pillar/global.sls` file.
3. Add the script to your managed files.
4. Schedule the script to run as a daily cron job.

### Known Issue
This script revealed an issue in our deployment related to Filebeat keeping many deleted files open. Our deployment experienced frequent crashes, which led to an accumulation of logs in the `/nsm/zeek/spool/tmp/*/` directories. When these files were eventually deleted, they remained open and caused a discrepancy between the output of `df /nsm` and `du -sch /nsm`. This resulted in cascading consequences that negatively impacted our deployment.

To identify if your deployment is affected by this issue, run the following command:

```
lsof /nsm | grep deleted | grep -c filebeat
```

A non-zero result indicates that you should investigate your Filebeat configuration. We are still working on resolving this issue in our deployment.
