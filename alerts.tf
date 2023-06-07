locals {
  alerts = [
    # 4.1 Ensure a log metric filter and alarm exist for unauthorized API calls
    {
      name                = "UnauthorizedAPICalls"
      description         = "Tracks unauthorized API calls."
      pattern             = "{ (($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")) && (($.sourceIPAddress != delivery.logs.amazonaws.com) || ($.eventName != HeadBucket)) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA
    {
      name                = "ConsoleSignInWithoutMFA"
      description         = "Tracks console logins that are not protected by multi-factor authentication (MFA)."
      pattern             = "{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != Yes) && ($.userIdentity.type = IAMUser) && ($.responseElements.ConsoleLogin = Success) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.3 Ensure a log metric filter and alarm exist for usage of "root" account
    {
      name                = "UsageOfRootAccount"
      description         = "Tracks root account activity."
      pattern             = "{ $.userIdentity.type = Root && $.userIdentity.invokedBy NOT EXISTS && $.eventType != AwsServiceEvent }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.4 Ensure a log metric filter and alarm exist for IAM policy changes
    {
      name                = "IAMPolicyChanges"
      description         = "Tracks changes made to Identity and Access Management (IAM) policies."
      pattern             = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy)}"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
    {
      name                = "CloudTrailChanges"
      description         = "Tracks changes to CloudTrail's configurations."
      pattern             = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
    {
      name                = "ManagementConsoleAuthenticationFailures"
      description         = "Tracks failed console authentication attempts."
      pattern             = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
    {
      name                = "DisablingOrDeletionOfCMK"
      description         = "Tracks customer-created CMKs that change to a disabled or scheduled deletion state."
      pattern             = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes
    {
      name                = "S3BucketPolicyChanges"
      description         = "Tracks changes to S3 bucket policies."
      pattern             = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
    {
      name                = "ConfigChanges"
      description         = "Tracks changes to AWS Config configurations."
      pattern             = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder))}"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.10 Ensure a log metric filter and alarm exist for security group changes
    {
      name                = "SecurityGroupChanges"
      description         = "Tracks changes made to security groups."
      pattern             = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
    {
      name                = "NACLChanges"
      description         = "Tracks changes made to NACLs."
      pattern             = "{ ($.eventName = CreateNetworkAcl) || ($.eventName =CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName =DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.12 Ensure a log metric filter and alarm exist for changes to network gateways
    {
      name                = "NetworkGatewayChanges"
      description         = "Tracks changes to network gateways."
      pattern             = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.13 Ensure a log metric filter and alarm exist for route table changes
    {
      name                = "RTBChanges"
      description         = "Tracks changes to route tables."
      pattern             = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.14 Ensure a log metric filter and alarm exist for VPC changes
    {
      name                = "VPCChanges"
      description         = "Tracks changes made to VPCs."
      pattern             = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) ||($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) ||($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) ||($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    },

    # 4.15 Ensure a log metric filter and alarm exist for changes made in the master AWS Account
    {
      name                = "OrganizationChanges"
      description         = "Tracks organization changes made in the master AWS Account."
      pattern             = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) ||($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit)|| ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) ||($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
      evaluation_periods  = 1
      threshold           = 1
      period              = 300
      comparison_operator = "GreaterThanOrEqualToThreshold"
      statistic           = "Sum"
    }
  ]
}
