#!/usr/bin/env python3
"""
Diagrama de arquitectura Zero Trust para FinCloud Invest
usando iconos OFICIALES de AWS via diagrams library.

Ejecutar: python3 diagrama_zero_trust_aws.py
Requiere: pip install diagrams
"""
from diagrams import Diagram, Cluster, Edge

# AWS Icons - official AWS architecture icons
from diagrams.aws.network import CloudFront, APIGateway, ALB, InternetGateway, NATGateway
from diagrams.aws.compute import ECS, EKS
from diagrams.aws.storage import S3
from diagrams.aws.database import RDS
from diagrams.aws.security import IAM, Cognito, SecretsManager, KMS, WAF, Guardduty
from diagrams.aws.management import Cloudwatch
from diagrams.onprem.network import Internet

graph_attr = {
    "pad": "1.5",
    "nodesep": "1.0",
    "ranksep": "1.5",
    "bgcolor": "white",
    "fontsize": "22",
    "fontcolor": "#232F3E",
}

cluster_attr = {
    "bgcolor": "#F8F9FA",
    "style": "rounded",
    "color": "#232F3E",
    "fontcolor": "#232F3E",
    "fontsize": "14",
    "fontname": "Helvetica",
    "margin": "25",
}

with Diagram(
    "FinCloud Zero Trust Architecture",
    show=False,
    direction="TB",
    outformat="png",
    filename="fincloud_zero_trust_aws_official",
    graph_attr=graph_attr,
):

    internet = Internet("Internet")

    with Cluster("Identity & Access", graph_attr=cluster_attr):
        cognito = Cognito("Amazon Cognito\nMFA + OAuth 2.0")
        iam_idc = IAM("IAM Identity Center\nSSO + Admin MFA")

    with Cluster("Edge & Distribution", graph_attr=cluster_attr):
        cf = CloudFront("CloudFront\nCDN + HTTPS")
        waf = WAF("AWS WAF\nRate Limit / Bot Control")

    with Cluster("API & Load Balancing", graph_attr=cluster_attr):
        alb = ALB("Application LB\nTLS 1.3 Termination")
        apigw = APIGateway("API Gateway\nAuthZ / Throttling")

    with Cluster("VPC - Production Environment", graph_attr={**cluster_attr, "bgcolor": "#F0F4F8", "style": "dashed,rounded", "margin": "30"}):

        with Cluster("Public Subnet", graph_attr={**cluster_attr, "bgcolor": "#FFF8E1"}):
            igw = InternetGateway("Internet Gateway")
            nat = NATGateway("NAT Gateway")
            ecs_web = ECS("ECS Web Tier\n(Reverse Proxy)")

        with Cluster("Private Subnet - Application", graph_attr={**cluster_attr, "bgcolor": "#E8F5E9"}):
            app = EKS("EKS / ECS\nApp Workloads")
            secrets = SecretsManager("Secrets Manager\n+ Parameter Store")
            kms_app = KMS("AWS KMS\nKey Rotation")

        with Cluster("Private Subnet - Data", graph_attr={**cluster_attr, "bgcolor": "#E3F2FD"}):
            db = RDS("Amazon RDS\nEncrypted / Multi-AZ")
            s3_docs = S3("S3 Documents\nBucket Policy / SSE-KMS")

    with Cluster("Observability & Security Monitoring", graph_attr={**cluster_attr, "bgcolor": "#F3E5F5"}):
        guardduty = Guardduty("Amazon GuardDuty\nThreat Detection")
        logs = Cloudwatch("CloudWatch / SIEM\nCorrelation / UEBA")

    # --- Flows ---

    internet >> Edge(label="HTTPS / TLS 1.3", color="#59A449", fontcolor="#59A449", fontsize="10") >> cf
    cf >> Edge(color="#232F3E") >> waf
    waf >> Edge(color="#232F3E") >> alb
    alb >> Edge(color="#232F3E") >> apigw

    cognito >> Edge(label="JWT / OIDC", style="dashed", color="#FF9900", fontcolor="#FF9900", fontsize="10") >> apigw
    iam_idc >> Edge(label="SSO / SAML", style="dashed", color="#FF9900", fontcolor="#FF9900", fontsize="10") >> alb

    apigw >> Edge(color="#232F3E") >> ecs_web
    ecs_web >> Edge(color="#232F3E") >> app

    app >> Edge(label="Retrieve", color="#59A449", fontcolor="#59A449", fontsize="10") >> secrets
    secrets >> Edge(label="Encrypt/Decrypt", style="dashed", color="#146EB4", fontcolor="#146EB4", fontsize="10") >> kms_app

    app >> Edge(label="mTLS / IAM Role", color="#59A449", fontcolor="#59A449", fontsize="10") >> db
    app >> Edge(label="IAM Role", color="#59A449", fontcolor="#59A449", fontsize="10") >> s3_docs

    db >> Edge(label="Encrypt/Decrypt", style="dashed", color="#146EB4", fontcolor="#146EB4", fontsize="10") >> kms_app
    s3_docs >> Edge(label="SSE-KMS", style="dashed", color="#146EB4", fontcolor="#146EB4", fontsize="10") >> kms_app

    # Monitoring flows
    app >> Edge(label="Logs / Metrics", style="dotted", color="#232F3E", fontsize="9") >> logs
    apigw >> Edge(label="Access Logs", style="dotted", color="#232F3E", fontsize="9") >> logs
    waf >> Edge(label="WAF Logs", style="dotted", color="#232F3E", fontsize="9") >> logs
    guardduty >> Edge(label="Findings", style="dotted", color="#232F3E", fontsize="9") >> logs
