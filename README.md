# AWS Public Endpoints Identification

A script that will identify all external endpoints (such as services or resources) in your AWS environment that are accessible from the internet, it can be also verifying if the endpoints are able to connect over the open ports.

### Instructions to Run the Script with Command-Line Arguments:

### To run the script and specify profiles, regions, and optionally the output CSV file, with connectivity verification:

```bash
python identify_public_endpoints.py --profiles profile1 profile2 --regions us-east-1 us-west-1 eu-west-1 --verify --output public_endpoints.csv

```

### To run the script and print results to stdout without writing to a CSV file, with connectivity verification:

```bash
python identify_public_endpoints.py --profiles okta-profile1 okta-profile2 --regions us-east-1 us-west-1 eu-west-1 --verify
```

### To run the script and print results to stdout without writing to a CSV file, without connectivity verification:

```bash
python identify_public_endpoints.py --profiles okta-profile1 okta-profile2 --regions us-east-1 us-west-1 eu-west-1
```

### Requirements 
Ensure you have the AWS SDK for Python (Boto3) installed.

### Example CSV Output
| Region	| Profile	| Type	| ID	| Name	| PublicIP	| SecurityGroup	| OpenPorts	| Connectivity |
| -------- | ------- |
| us-east-1 | profile1 | EC2 | i-0a12345678901234 | Node-1 | 1.2.3.4 | sg-0123456789012345 | 22-22(tcp) | 22-22(tcp): 22: Failure |
| us-west-1 | profile2 | EC2 | i-0a12345678901235 | Node-2 | 1.2.3.5 | sg-0123456789012346 | 22-22(tcp) | 22-22(tcp): 22: Success |