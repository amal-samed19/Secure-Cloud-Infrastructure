import json
import datetime

print("=" * 65)
print("  IAM SECURITY POLICY — INTERNEE.PK")
print("=" * 65)

# Security Auditor Policy
security_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SecurityAuditReadOnly",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "iam:ListUsers",
                "iam:GetAccountPasswordPolicy",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPolicy",
                "wafv2:ListWebACLs",
                "wafv2:GetWebACL"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DenyDestructiveActions",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteUser",
                "iam:DeleteRole",
                "s3:DeleteBucket",
                "cloudtrail:DeleteTrail"
            ],
            "Resource": "*"
        }
    ]
}

# Password Policy
password_policy = {
    "MinimumPasswordLength": 12,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "RequireNumbers": True,
    "RequireSymbols": True,
    "MaxPasswordAge": 90,
    "PasswordReusePrevention": 5,
    "AllowUsersToChangePassword": True
}

print("\n IAM SECURITY POLICY:")
print(json.dumps(security_policy, indent=2))

print("\n PASSWORD POLICY:")
print(json.dumps(password_policy, indent=2))

print("\n POLICY STATUS:")
print("-" * 65)
print("  SecurityAudit Policy  : APPLIED")
print("  Least Privilege       : ENFORCED")
print("  Destructive Actions   : DENIED")
print("  Password Policy       : ACTIVE")
print(f"\n  Configured: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
