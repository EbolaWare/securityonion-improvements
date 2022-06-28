# securityonion-improvements
Collection of things I've developed in my journey making a Security Onion cluster capable of handling a massive enterprise.

## 1. ./log-scrubber.sh
Allows for configuring log retention (maximums and minimums via SaltStack's pillar). Currently supports only zeek logs. Zeek logs were the only ones causing issues in our deployment. [SecurityOnion Issue #7774](https://github.com/Security-Onion-Solutions/securityonion/issues/7774) <br>
Add it to your deployment, configure alternate settings in your pillar (global.sls). Add it to your managed files, then put it in your cron jobs. One daily task should suffice. <br>
An issue that this highlighted in our deployment: Filebeat was keeping a lot of (deleted) files open. Our deployment suffers from frequent crashes, resulting in a lot of logs being moved into the `/nsm/zeek/spool/tmp/*/` directories. When those files finally were deleted, by this script or any other means, they were left open and hanging. This created a disparity between `df /nsm` and `du -sch /nsm`. This had cascading results of an undesirable nature. This was discovered by running `lsof /nsm | grep deleted | grep -c filebeat` a result of any number here means you need to dig into your filebeat config as we are still doing a week later. <br>
