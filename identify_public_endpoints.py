import boto3
import csv
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, NoRegionError

def get_boto3_session(profile_name, region_name):
    try:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        return session
    except (NoCredentialsError, PartialCredentialsError, NoRegionError) as e:
        print(f"Error: {e}")
        return None

def get_security_group_ports(session, security_group_ids):
    ec2 = session.client('ec2')
    response = ec2.describe_security_groups(GroupIds=security_group_ids)
    open_ports = {}
    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        open_ports[sg_id] = []
        for perm in sg.get('IpPermissions', []):
            if 'FromPort' in perm and 'ToPort' in perm:
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_ports[sg_id].append((perm['FromPort'], perm['ToPort'], perm.get('IpProtocol', 'unknown')))
                for ipv6_range in perm.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        open_ports[sg_id].append((perm['FromPort'], perm['ToPort'], perm.get('IpProtocol', 'unknown')))
    return open_ports

def get_instance_name(instance):
    name = None
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            name = tag['Value']
            break
    return name

def get_public_ec2_instances(session, open_ports):
    ec2 = session.client('ec2')
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    public_instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'PublicIpAddress' in instance:
                for sg in instance['SecurityGroups']:
                    sg_id = sg['GroupId']
                    if sg_id in open_ports and open_ports[sg_id]:
                        instance_info = {
                            'Region': session.region_name,
                            'Profile': session.profile_name,
                            'Type': 'EC2',
                            'ID': instance['InstanceId'],
                            'Name': get_instance_name(instance),
                            'PublicIP': instance['PublicIpAddress'],
                            'SecurityGroup': sg_id,
                            'OpenPorts': open_ports[sg_id]
                        }
                        public_instances.append(instance_info)
                        break
    return public_instances

def get_public_load_balancers(session, open_ports):
    elb = session.client('elb')
    elbv2 = session.client('elbv2')
    response_elb = elb.describe_load_balancers()
    response_elbv2 = elbv2.describe_load_balancers()
    public_elbs = []
    public_elbv2s = []
    for lb in response_elb['LoadBalancerDescriptions']:
        if lb.get('Scheme') == 'internet-facing':
            for sg_id in lb.get('SecurityGroups', []):
                if sg_id in open_ports and open_ports[sg_id]:
                    lb_info = {
                        'Region': session.region_name,
                        'Profile': session.profile_name,
                        'Type': 'ELB',
                        'ID': lb['LoadBalancerName'],
                        'Name': lb['LoadBalancerName'],
                        'PublicIP': lb['DNSName'],
                        'SecurityGroup': sg_id,
                        'OpenPorts': open_ports[sg_id]
                    }
                    public_elbs.append(lb_info)
                    break
    for lb in response_elbv2['LoadBalancers']:
        if lb.get('Scheme') == 'internet-facing':
            for sg_id in lb.get('SecurityGroups', []):
                if sg_id in open_ports and open_ports[sg_id]:
                    lb_info = {
                        'Region': session.region_name,
                        'Profile': session.profile_name,
                        'Type': 'ALB/NLB',
                        'ID': lb['LoadBalancerName'],
                        'Name': lb['LoadBalancerName'],
                        'PublicIP': lb['DNSName'],
                        'SecurityGroup': sg_id,
                        'OpenPorts': open_ports[sg_id]
                    }
                    public_elbv2s.append(lb_info)
                    break
    return public_elbs, public_elbv2s

def get_public_rds_instances(session, open_ports):
    rds = session.client('rds')
    response = rds.describe_db_instances()
    public_rds = []
    for db in response['DBInstances']:
        if db.get('PubliclyAccessible'):
            for sg in db['VpcSecurityGroups']:
                sg_id = sg['VpcSecurityGroupId']
                if sg_id in open_ports and open_ports[sg_id]:
                    db_info = {
                        'Region': session.region_name,
                        'Profile': session.profile_name,
                        'Type': 'RDS',
                        'ID': db['DBInstanceIdentifier'],
                        'Name': db['DBInstanceIdentifier'],
                        'PublicIP': db['Endpoint']['Address'],
                        'SecurityGroup': sg_id,
                        'OpenPorts': open_ports[sg_id]
                    }
                    public_rds.append(db_info)
                    break
    return public_rds

def collect_security_group_ids(session):
    security_group_ids = set()

    # Collect all security group IDs from EC2 instances, ELBs, and RDS instances
    ec2 = session.client('ec2')
    instances_response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            for sg in instance['SecurityGroups']:
                security_group_ids.add(sg['GroupId'])

    elb = session.client('elb')
    elbv2 = session.client('elbv2')
    elb_response = elb.describe_load_balancers()
    elbv2_response = elbv2.describe_load_balancers()
    for lb in elb_response['LoadBalancerDescriptions']:
        for sg in lb.get('SecurityGroups', []):
            security_group_ids.add(sg)

    for lb in elbv2_response['LoadBalancers']:
        for sg in lb.get('SecurityGroups', []):
            security_group_ids.add(sg)

    rds = session.client('rds')
    rds_response = rds.describe_db_instances()
    for db in rds_response['DBInstances']:
        for sg in db['VpcSecurityGroups']:
            security_group_ids.add(sg['VpcSecurityGroupId'])

    return list(security_group_ids)

def verify_connectivity(public_ip, port):
    try:
        with socket.create_connection((public_ip, port), timeout=5):
            return "Success"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "Failure"

def verify_endpoint_connectivity(endpoint):
    connectivity_results = {}
    for port_range in endpoint['OpenPorts']:
        from_port, to_port, protocol = port_range
        results = []
        for port in range(from_port, to_port + 1):
            result = verify_connectivity(endpoint['PublicIP'], port)
            results.append(f"{port}: {result}")
        connectivity_results[port_range] = "; ".join(results)
    return endpoint, connectivity_results

def main():
    parser = argparse.ArgumentParser(description='Identify publicly accessible AWS endpoints.')
    parser.add_argument('--profiles', nargs='+', required=True, help='AWS profiles to use.')
    parser.add_argument('--regions', nargs='+', required=True, help='AWS regions to check.')
    parser.add_argument('--output', type=str, help='CSV file to write the results to (optional).')
    parser.add_argument('--verify', action='store_true', help='Verify connectivity to open ports.')

    args = parser.parse_args()
    profile_names = args.profiles
    regions = args.regions
    output_file = args.output
    verify = args.verify

    all_public_endpoints = []

    for profile_name in profile_names:
        for region in regions:
            print(f"\nProfile: {profile_name}, Region: {region}")
            session = get_boto3_session(profile_name, region)
            if not session:
                print(f"Failed to create a Boto3 session for profile {profile_name} and region {region}.")
                continue

            security_group_ids = collect_security_group_ids(session)

            # Get open ports for these security groups
            open_ports = get_security_group_ports(session, security_group_ids)

            # Get public instances, load balancers, and RDS instances that are truly open to the internet
            public_ec2_instances = get_public_ec2_instances(session, open_ports)
            public_elbs, public_elbv2s = get_public_load_balancers(session, open_ports)
            public_rds_instances = get_public_rds_instances(session, open_ports)

            all_public_endpoints.extend(public_ec2_instances)
            all_public_endpoints.extend(public_elbs)
            all_public_endpoints.extend(public_elbv2s)
            all_public_endpoints.extend(public_rds_instances)

    if verify:
        with ThreadPoolExecutor() as executor:
            future_to_endpoint = {executor.submit(verify_endpoint_connectivity, endpoint): endpoint for endpoint in all_public_endpoints}
            for future in as_completed(future_to_endpoint):
                endpoint, connectivity = future.result()
                endpoint['Connectivity'] = connectivity

    if output_file:
        # Write results to CSV file
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Region', 'Profile', 'Type', 'ID', 'Name', 'PublicIP', 'SecurityGroup', 'OpenPorts', 'Connectivity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for endpoint in all_public_endpoints:
                writer.writerow({
                    'Region': endpoint['Region'],
                    'Profile': endpoint['Profile'],
                    'Type': endpoint['Type'],
                    'ID': endpoint['ID'],
                    'Name': endpoint['Name'],
                    'PublicIP': endpoint['PublicIP'],
                    'SecurityGroup': endpoint['SecurityGroup'],
                    'OpenPorts': '; '.join([f"{port[0]}-{port[1]}({port[2]})" for port in endpoint['OpenPorts']]),
                    'Connectivity': '; '.join([f"{port[0]}-{port[1]}({port[2]}): {result}" for port, result in endpoint.get('Connectivity', {}).items()])
                })

        print(f"\nResults have been written to {output_file}")
    else:
        # Print results to stdout
        print(f"{'Region':<15} {'Profile':<15} {'Type':<10} {'ID':<25} {'Name':<25} {'PublicIP':<20} {'SecurityGroup':<20} {'OpenPorts'} {'Connectivity'}")
        for endpoint in all_public_endpoints:
            open_ports_str = '; '.join([f"{port[0]}-{port[1]}({port[2]})" for port in endpoint['OpenPorts']])
            connectivity_str = '; '.join([f"{port[0]}-{port[1]}({port[2]}): {result}" for port, result in endpoint.get('Connectivity', {}).items()])
            print(f"{endpoint['Region']:<15} {endpoint['Profile']:<15} {endpoint['Type']:<10} {endpoint['ID']:<25} {endpoint['Name']:<25} {endpoint['PublicIP']:<20} {endpoint['SecurityGroup']:<20} {open_ports_str} {connectivity_str}")

if __name__ == "__main__":
    main()
