import imaplib
import email
from email.header import decode_header
from common.helper import *

email_address = ""

def clean(text):
    # clean text for creating a folder
    return "".join(c if c.isalnum() else "_" for c in text)

def walk_email(msg):
    for response in msg:
        if isinstance(response, tuple):
            # parse a bytes email into a message object
            msg = email.message_from_bytes(response[1])
            # decode the email subject
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                # if it's a bytes, decode to str
                subject = subject.decode(encoding)
            # decode email sender
            From, encoding = decode_header(msg.get("From"))[0]
            if isinstance(From, bytes):
                From = From.decode(encoding)
            # if the email message is multipart
            if msg.is_multipart():
                # iterate over email parts
                for part in msg.walk():
                    # extract content type of email
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    # get the email body
                    body = part.get_payload(decode=True)
                    if body is None:
                        continue
                    body = body.decode()
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        # print text/plain emails and skip attachments
                        return subject, body
                    elif "attachment" in content_disposition:
                        return subject, ''
            #                     # download attachment
    #                     filename = part.get_filename()
    #                     if filename:
    #                         folder_name = clean(subject)
    #                         if not os.path.isdir(folder_name):
    #                             # make a folder for this email (named after the subject)
    #                             os.mkdir(folder_name)
    #                         filepath = os.path.join(folder_name, filename)
    #                         # download attachment and save it
    #                         open(filepath, "wb").write(part.get_payload(decode=True))
            else:
                # extract content type of email
                content_type = msg.get_content_type()
                # get the email body
                body = msg.get_payload(decode=True).decode()
                if content_type == "text/plain":
                    # print only text email parts
                    return subject, body
            if content_type == "text/html":
                return subject, body
            #     # if it's HTML, create a new HTML file and open it in browser
            #     folder_name = clean(subject)
            #     if not os.path.isdir(folder_name):
            #         # make a folder for this email (named after the subject)
            #         os.mkdir(folder_name)
            #     filename = "index.html"
    #             filepath = os.path.join(folder_name, filename)
    #             # write the file
    # #             open(filepath, "w").write(body)
    # #             # open in the default browser
    # #             webbrowser.open(filepath)
    # #         print("="*100)

import requests
def handle_confirmation_email(client, user_pool_client_id, username):
    # account credentials
    password = ""
    # use your email provider's IMAP server, you can look for your provider's IMAP server on Google
    # or check this page: https://www.systoolsgroup.com/imap/
    # for office 365, it's this:
    imap_server = "imap.gmail.com"
    # create an IMAP4 class with SSL
    imap = imaplib.IMAP4_SSL(imap_server)
    # authenticate
    imap.login(email_address, password)
    status, messages = imap.select("INBOX")
    # number of top emails to fetch
    N = 1
    # total number of emails
    code = None
    messages = int(messages[0])
    if messages == 0:
        return 'retry'

    confirm_success = False
    for i in range(messages, 0, -1):
        # fetch the email message by ID
        res, msg = imap.fetch(str(i), "(RFC822)")
        subject, body = walk_email(msg)
        code_results = search_regex(body, re.compile('\d{6}'), [], 0, True)
        for code in code_results:
            # client.admin_confirm_sign_up(UserPoolId=user_pool_id, Username=json_data['user_pool_client_username'])
            try:
                client.confirm_sign_up(ClientId=user_pool_client_id, Username=username, ConfirmationCode=code)
                confirm_success = True
                break
            except Exception as e:
                if 'please request a code again' in str(e):
                    return 'retry'
        if confirm_success:
            break

        links = search_regex(body, re.compile('<a href=(\'")?(.+)[>"\']'), [], 2, True)
        for link in links:
            response = requests.get(link, headers=pass_403_headers)
            if response.status_code == 200 and 'error ' not in response.text:
                confirm_success = True
                break
            # elif code in body:
            #     code = None
            #     start_index = body.rindex('code')
            #     code_area = body[start_index:start_index + min(500, len(body) - start_index)]
            #     # code_area = search_regex(msg_str, re.compile('.{0,20}code.{0,80}'), [], 0, False)[0]
            #     codes = search_regex(code_area, re.compile('\d{6}'), [], 0, False)
            #     if len(codes) > 0:
            #         code = codes[0]
            #     break
        if confirm_success:
            break
        else:
            return 'retry'
    # close the connection and logout
    imap.expunge() #doesn`t work currently # imap.store(msg, "+FLAGS", "\\Deleted")
    imap.close()
    imap.logout()
    if confirm_success:
        return 'success'
