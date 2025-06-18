import boto3
 
role_to_assume = 'CloudAdminReadOnly'                  
regions = ['us-east-1']
 
MAX_RULES_PER_SG = 200
SG_RULE_ALERT_THRESHOLD = 160
MAX_SGS_PER_ENI = 5
MAX_RULES_PER_ENI = 1000
ENI_RULE_ALERT_THRESHOLD = 800
 
def get_all_accounts():
    # Create Organizations client
    org_client = boto3.client('organizations')
   
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
   
    # Iterate through all accounts in the organization
    for page in paginator.paginate():
        for account in page['Accounts']:
            if account['Status'] == 'ACTIVE':  # Only include active accounts
                accounts.append(account['Id'])
   
    return accounts
 
def count_rules(permission_list):
    count = 0
    for perm in permission_list:
        count += len(perm.get('IpRanges', []))
        count += len(perm.get('Ipv6Ranges', []))
        count += len(perm.get('UserIdGroupPairs', []))
        count += len(perm.get('PrefixListIds', []))
    return count
 
def main():
    sts_client = boto3.client('sts')
   
    # Get all accounts in the organization
    target_accounts = get_all_accounts()
   
    for account_id in target_accounts:
        role_arn = f'arn:aws:iam::{account_id}:role/{role_to_assume}'
        print(f"Assuming role in Account {account_id}...")
       
        try:
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"AuditSession-{account_id}"
            )
           
            credentials = assumed_role['Credentials']
           
            for region in regions:
                print(f"Checking account {account_id} | region {region}")
                ec2 = boto3.client(
                    'ec2',
                    region_name=region,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
               
                # Check Security Groups
                try:
                    for sg in ec2.describe_security_groups()['SecurityGroups']:
                        sg_id = sg['GroupId']
                        sg_name = sg.get('GroupName', '')
                        in_rules = count_rules(sg['IpPermissions'])
                        out_rules = count_rules(sg['IpPermissionsEgress'])
                        total = in_rules + out_rules
                        flagged = "YES" if total >= SG_RULE_ALERT_THRESHOLD else "NO"
                        print(f"{region:<12} {'SG':<6} {sg_id:<20} {'':<5} {total:<8} {round((total/MAX_RULES_PER_SG)*100,2):<8} {flagged} {sg_name}")
                except Exception as e:
                    print(f"Error checking SGs in account {account_id}, region {region}: {str(e)}")
               
                # Check Network Interfaces
                try:
                    for eni in ec2.describe_network_interfaces()['NetworkInterfaces']:
                        eni_id = eni['NetworkInterfaceId']
                        sg_ids = [sg['GroupId'] for sg in eni['Groups']]
                        sg_count = len(sg_ids)
                        total_rules = 0
                        for sg_id in sg_ids:
                            sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                            total_rules += count_rules(sg['IpPermissions']) + count_rules(sg['IpPermissionsEgress'])
                        usage_pct = round((total_rules / MAX_RULES_PER_ENI) * 100, 2)
                        flagged = "YES" if total_rules >= ENI_RULE_ALERT_THRESHOLD or sg_count > MAX_SGS_PER_ENI else "NO"
                        print(f"{region:<12} {'ENI':<6} {eni_id:<20} {sg_count:<5} {total_rules:<8} {usage_pct:<8} {flagged}")
                except Exception as e:
                    print(f"Error checking ENIs in account {account_id}, region {region}: {str(e)}")
                   
        except Exception as e:
            print(f"Error assuming role in account {account_id}: {str(e)}")
 
if __name__ == "__main__":
    main()