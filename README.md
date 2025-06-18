Security group rule limit is 1000, which is a hard limit.
Default security group count is 5, the 1000 cap is limited by the total across all security groups on the ENI.
This script will help pull all the org security group rule counts and help determine if you are reaching a hard set limit. SG limit can be increased from 200 to 250 if you reduce the allowed SG from 5 to 4.
