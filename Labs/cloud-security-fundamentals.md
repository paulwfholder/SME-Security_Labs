## **Cloud Security Lab: Securing and Monitoring a Cloud Environment**

### Lab Objective:
This lab introduces essential cloud security practices, focusing on securing cloud resources, configuring access controls, monitoring for threats, and understanding cloud-specific security features. You’ll use AWS as the primary environment, but the concepts can be applied to other cloud providers (Azure, Google Cloud).

---

### **Scenario**:
Your organization recently migrated critical applications and data to the cloud. As a security engineer, your task is to ensure this environment is secure and complies with best practices. You’ll configure Identity and Access Management (IAM) roles and policies, secure network configurations, monitor for unusual activities, and implement automated incident response.

The lab includes four main parts:
1. **Identity and Access Management (IAM) Configuration**
2. **Network Security with Security Groups**
3. **Cloud Monitoring and Alerting**
4. **Automated Cloud Response for Security Events**

---

### **Part 1: Identity and Access Management (IAM) Configuration**

1. **Objective**: Set up least-privilege access controls by creating roles and policies that limit user permissions to only what is necessary.

2. **Setting Up IAM Roles and Policies**:
   - **Step 1**: Create an IAM role named `ReadOnly-EC2-Role` with read-only permissions for EC2.
     - In the AWS Console, navigate to IAM > Roles > Create Role.
     - Select **AWS Service** and choose **EC2**.
     - Attach the `AmazonEC2ReadOnlyAccess` policy to the role.
   
   - **Step 2**: Create a custom policy with specific S3 permissions to access a certain bucket only.
     - Use the following JSON policy to limit access to a single bucket:
       ```json
       {
         "Version": "2012-10-17",
         "Statement": [
           {
             "Effect": "Allow",
             "Action": [
               "s3:GetObject",
               "s3:ListBucket"
             ],
             "Resource": [
               "arn:aws:s3:::example-bucket",
               "arn:aws:s3:::example-bucket/*"
             ]
           }
         ]
       }
       ```
     - Attach this policy to a role named `RestrictedS3Access`.

3. **IAM Best Practices**:
   - Enforce **MFA (Multi-Factor Authentication)** for all IAM users.
   - Disable unused IAM accounts or roles.
   - Periodically review IAM permissions and rotate access keys every 90 days.

4. **Lab Task**:
   - Provide screenshots of IAM roles created, policies attached, and MFA enabled for at least one user.

---

### **Part 2: Network Security with Security Groups**

1. **Objective**: Configure security groups to control inbound and outbound traffic to cloud resources.

2. **Configuring Security Groups**:
   - **Step 1**: Create a security group for a web server that allows HTTP and HTTPS traffic only from specific IP ranges.
     - In the AWS Console, go to EC2 > Security Groups > Create Security Group.
     - Name it `WebServer-SG` and add rules:
       - **Inbound**: Allow **HTTP** (port 80) and **HTTPS** (port 443) from `0.0.0.0/0`.
       - **Outbound**: Allow all traffic (to support app connectivity).
   
   - **Step 2**: Create a security group for a database server that allows connections only from the web server’s security group.
     - Name the security group `DB-SG`.
     - Configure inbound rules:
       - Allow MySQL (port 3306) from `WebServer-SG` (using the security group ID).
   
3. **Testing Security Groups**:
   - Attempt to connect to the database from an unauthorized IP to confirm it’s restricted.
   - Run `curl` or `wget` commands from the web server to check HTTP access.

4. **Lab Task**:
   - Document the configurations with screenshots of security group rules.
   - Note any access issues encountered during testing.

---

### **Part 3: Cloud Monitoring and Alerting**

1. **Objective**: Set up monitoring and alerts for key resources, such as unusual login attempts or high-CPU usage events.

2. **Enabling AWS CloudTrail**:
   - Enable CloudTrail to log all account activities.
   - In the AWS Console, go to CloudTrail > Trails > Create Trail.
   - Select **All regions** to capture activity across the entire account.
   - Store CloudTrail logs in an S3 bucket for analysis.
   
3. **Configuring CloudWatch Alarms**:
   - **Step 1**: Create a CloudWatch alarm for high CPU usage on EC2 instances.
     - In CloudWatch, go to Alarms > Create Alarm.
     - Select an EC2 instance as the resource and set the alarm to trigger if CPU usage exceeds 80% for 5 minutes.
     - Set up an SNS (Simple Notification Service) topic to receive email alerts.

   - **Step 2**: Create a CloudWatch alarm for unauthorized access attempts.
     - Set up a filter in CloudTrail to capture `UnauthorizedOperation` events.
     - Create an alarm based on this filter and send alerts to the same SNS topic.

4. **Lab Task**:
   - Trigger a test alert by simulating high CPU usage (e.g., running a CPU-intensive task).
   - Document the setup with screenshots of the CloudTrail trail, CloudWatch alarms, and SNS configuration.

---

### **Part 4: Automated Cloud Response for Security Events**

1. **Objective**: Implement automated response actions to contain and remediate security incidents.

2. **Lambda Function for Automated Remediation**:
   - Create a Lambda function that triggers upon detecting certain CloudWatch alarms, such as unauthorized access attempts.
   - **Step 1**: In Lambda, create a new function called `AutoBlockUnauthorizedIP`.
     - Configure the function to read CloudTrail logs and parse IP addresses from `UnauthorizedOperation` events.
     - Code example for blocking an IP by modifying a security group:
       ```python
       import boto3

       ec2 = boto3.client('ec2')
       
       def lambda_handler(event, context):
           ip_to_block = event['detail']['sourceIPAddress']
           response = ec2.authorize_security_group_ingress(
               GroupId='sg-xxxxxxxx',  # Replace with your security group ID
               IpProtocol='-1',
               CidrIp=f'{ip_to_block}/32'
           )
           return response
       ```
   - **Step 2**: Attach an IAM role to the Lambda function with permissions to modify security group rules.
   
3. **Testing Automated Response**:
   - Trigger the Lambda function manually or by simulating an unauthorized access attempt.
   - Verify that the IP address is automatically blocked in the security group.

4. **Lab Task**:
   - Document the Lambda setup with screenshots.
   - Include logs showing the Lambda function execution and the security group modification.

---

### **Lab Deliverables**:

1. **Configurations Repository**:
   - Upload the JSON policies, Python code, and Lambda function to the repository.

2. **Documentation and Screenshots**:
   - Document all steps and provide screenshots of IAM roles, security group configurations, CloudTrail/CloudWatch setups, and the Lambda function.

3. **Reflection Questions**:
   - How effective are the security group configurations in controlling network access?
   - What challenges did you face when setting up CloudWatch alarms and automating responses?
   - How would you improve the automated response actions for real-world environments?

---

This Cloud Security Lab prepares you to secure and monitor cloud environments, configure essential access controls, and apply automated incident response in a real-world cloud setting. With these skills, you’re now well-prepared for cloud-based security roles.
