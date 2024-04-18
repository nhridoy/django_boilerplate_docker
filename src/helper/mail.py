import smtplib
from email.mime.text import MIMEText

from django.core.mail import EmailMultiAlternatives, get_connection


def mail_sender(
    recipient_list: tuple | list,
    subject: str,
    from_email: str,
    body: str,
    attachment: bytes = None,
    attachment_name: str = None,
    cc: tuple | list = None,
    bcc: tuple | list = None,
    reply_to: tuple | list = None,
    html_message: str = None,
    auth_user: str = None,
    auth_password: str = None,
    smtp_host: str = None,
    smtp_port: int = None,
    use_tls: bool = False,
    use_ssl: bool = False,
):
    """
    Email sender function:
    It try to send mail using Django's default mail sender function
    if failed
    Then it uses python's smtplib
    """
    try:
        # Create a connection
        with get_connection(
            host=smtp_host,  # your SMTP server
            port=smtp_port,  # your SMTP port
            username=auth_user,  # your SMTP username
            password=auth_password,  # your SMTP password
            use_tls=use_tls,
            use_ssl=use_ssl,
        ) as connection:
            email_messages = [
                EmailMultiAlternatives(
                    subject=subject,
                    body=body,
                    from_email=from_email,
                    to=(recipient,),
                    cc=cc,
                    bcc=bcc,
                    reply_to=reply_to,
                    alternatives=(
                        ((html_message, "text/html"),) if html_message else None
                    ),
                )
                for recipient in recipient_list
            ]
            # Attach the file to the email messages
            if attachment and attachment_name:
                # filename = os.path.basename(attachment.name)
                # file_content = attachment.read()
                for email_message in email_messages:
                    email_message.attach(
                        filename=attachment_name,
                        content=attachment,
                    )

            # Open a single connection for all the emails
            connection.open()

            # Send the emails in a single call
            connection.send_messages(email_messages)

    except Exception as e:
        print(e)
        # Create server object with SSL option
        server = smtplib.SMTP_SSL(smtp_host, smtp_port)

        # Perform operations via server
        server.login(auth_user, auth_password)

        # Create message

        for recipient in recipient_list:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = from_email
            msg["To"] = recipient

            server.sendmail(from_email, [recipient], msg.as_string())

        server.quit()
