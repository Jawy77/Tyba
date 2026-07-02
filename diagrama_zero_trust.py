#!/usr/bin/env python3
"""
Diagrama de arquitectura Zero Trust propuesta para FinCloud Invest.
Requiere: pip install diagrams
"""
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import CloudFront, APIGateway, ALB, VPC, PrivateSubnet, PublicSubnet
from diagrams.aws.compute import ECS, EKS
from diagrams.aws.storage import S3
from diagrams.aws.database import RDS
from diagrams.aws.security import IAM, SecretsManager, KMS, WAF
from diagrams.aws.management import Cloudwatch
from diagrams.onprem.client import Users, User
from diagrams.onprem.network import Internet
from diagrams.programming.language import Python

with Diagram(
    "FinCloud_Zero_Trust_Architecture",
    show=False,
    direction="TB",
    outformat="png",
    filename="fincloud_zero_trust_architecture",
    graph_attr={"pad": "0.5", "nodesep": "0.6", "ranksep": "1.0", "bgcolor": "white"},
):
    internet = Internet("Internet")

    with Cluster("Identity & Access"):
        cognito = User("Amazon Cognito\n(MFA + OAuth2)")
        iam_idc = IAM("IAM Identity Center\n(Admin MFA)")

    with Cluster("Edge & Distribution"):
        cf = CloudFront("CloudFront\n(HTTPS / WAF)")
        waf = WAF("AWS WAF\n(Rate Limit / Bot Control)")

    with Cluster("API & Load Balancing"):
        alb = ALB("Application LB\n(TLS 1.3 Termination)")
        apigw = APIGateway("API Gateway\n(AuthZ / Throttling)")

    with Cluster("VPC - Production"):
        with Cluster("Public Subnet"):
            public_web = ECS("ECS Web Tasks\n(Reverse Proxy)")

        with Cluster("Private Subnet - Application"):
            app = EKS("EKS / ECS\n(Workload)")
            secrets = SecretsManager("Secrets Manager\n+ Parameter Store")
            kms = KMS("AWS KMS\n(Envelope Encryption)")

        with Cluster("Private Subnet - Data"):
            db = RDS("Amazon RDS\n(Encrypted / Multi-AZ)")
            s3_docs = S3("S3 Documents\n(Bucket Policy / SSE-KMS)")

    with Cluster("Observability"):
        logs = Cloudwatch("CloudWatch / SIEM\n(Correlation / UEBA)")

    # Flows
    internet >> Edge(label="HTTPS", color="darkgreen") >> cf
    cf >> waf >> alb >> apigw

    cognito >> Edge(label="JWT / OIDC", style="dashed") >> apigw
    iam_idc >> Edge(label="SSO / SAML", style="dashed") >> alb

    apigw >> public_web >> app
    app >> Edge(label="mTLS / IAM Role") >> db
    app >> Edge(label="IAM Role / IRSA") >> s3_docs
    app >> Edge(label="Retrieve") >> secrets
    secrets >> Edge(label="Encrypt/Decrypt") >> kms
    db >> Edge(label="Encrypt/Decrypt") >> kms
    s3_docs >> Edge(label="SSE-KMS") >> kms

    # Monitoring
    app >> Edge(label="Logs / Metrics", style="dotted", color="blue") >> logs
    apigw >> Edge(label="Access Logs", style="dotted", color="blue") >> logs
    waf >> Edge(label="WAF Logs", style="dotted", color="blue") >> logs
