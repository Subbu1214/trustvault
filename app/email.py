"""Email delivery service using AWS SES with local development/testing fallback."""
import logging
import boto3
from botocore.exceptions import ClientError
from flask import current_app

logger = logging.getLogger("trustvault.email")


def send_email(to_email, subject, body_text, body_html=None):
    """
    Sends an email using AWS SES in production.
    In testing, local development, or when SES_SENDER is not configured,
    logs the email content to stdout/logger.
    """
    sender = current_app.config.get("SES_SENDER")
    region = current_app.config.get("AWS_REGION", "ap-south-1")
    is_testing = current_app.config.get("TESTING", False)
    is_dev = current_app.config.get("ENV") == "development" or not sender

    if is_testing or is_dev:
        msg = (
            f"\n{'=' * 65}\n"
            f"[EMAIL DISPATCH - LOCAL / SIMULATED]\n"
            f"To: {to_email}\n"
            f"Subject: {subject}\n"
            f"Body:\n{body_text}\n"
            f"{'=' * 65}\n"
        )
        print(msg)
        logger.info(msg)
        return True

    try:
        client = boto3.client("ses", region_name=region)
        message_body = {"Text": {"Data": body_text, "Charset": "UTF-8"}}
        if body_html:
            message_body["Html"] = {"Data": body_html, "Charset": "UTF-8"}

        client.send_email(
            Source=sender,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": message_body,
            },
        )
        return True
    except ClientError as e:
        logger.error("Failed to send email via SES to %s: %s", to_email, e)
        return False
