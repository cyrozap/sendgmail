# sendgmail

sendgmail is a tool that uses Gmail in order to mimic `sendmail` for `git
send-email`.

This tool has been modified from its [original version](https://github.com/google/gmail-oauth2-tools/tree/578a11a744c37bd19c1c1b8d96061276dbf6f7f0/go/sendgmail).
This new version, inspired by [siketyan/sendgmail](https://github.com/siketyan/sendgmail),
uses the Gmail [users.messages.send API](https://developers.google.com/gmail/api/reference/rest/v1/users.messages/send)
instead of SMTP to send the email. This has the following advantages:

*   The scope of the OAuth token can be limited to only sending emails. This
    avoids the potential danger created by generating a token with full Gmail
    permissions, which is necessary to send emails through Gmail using SMTP
    (when not using an app password, which grants even more permissions).

*   Sent emails will always appear in the "Sent" folder in Gmail regardless of
    whether or not you CC yourself. In contrast, when a message is sent via
    SMTP, the message will not appear in the "Sent" folder unless you CC
    yourself.

## Obtaining OAuth2 credentials for sendgmail

1.  Go to the [Google Cloud console](https://console.cloud.google.com/).

    *   Create a new project. You probably want to name it something like
        *sendgmail* in **IAM & Admin > Settings** and also in **APIs &
        Services > OAuth consent screen**.

2.  Go to the
    [Go quickstart](https://developers.google.com/gmail/api/quickstart/go) page
    of the Gmail API documentation.

    *   Click the **Enable the API** button. It will open another page in your
        browser. Follow the steps on that page to enable the Gmail API for the
        project that you created.

    *   Follow the steps in the **Authorize credentials for a desktop
        application** section. However, set the application type to *Web
        application* (i.e. instead of *Desktop app*) and then add
        `https://oauth2.dance/` as an authorised redirect URI. This is necessary
        for seeing the authorisation code on a page in your browser.

    *   When you download the credentials as JSON, create the
        `${XDG_CONFIG_HOME:-${HOME}/.config}/sendgmail` directory with file mode
        `0700` and then save the file to that directory as `config.json` with
        file mode `0600`.

        For historical reasons, when the file named `config.json` does not exist
        under your config directory, sendgmail will try looking for a file named
        `.sendgmail.json` in your home directory.

3.  Go back to **APIs & Services > OAuth consent screen** in the Google Cloud
    console.

    *   Add `USERNAME@gmail.com` as a test user. This is necessary for using the
        project that you created.

    *   Add `https://www.googleapis.com/auth/gmail.send` as a scope. This is
        necessary for sending emails via the Gmail API.

## Installing sendgmail

Run the following command to build and install sendgmail to
`GOPATH/bin/sendgmail`:

```shell
go install github.com/cyrozap/sendgmail@latest
```

## Obtaining OAuth2 credentials for yourself

Run the following command to perform the OAuth2 dance:

```shell
GOPATH/bin/sendgmail -sender=USERNAME@gmail.com -setup
```

## Using sendgmail

Add the following section to `.gitconfig` in your home directory:

```
[sendemail]
    smtpServer = GOPATH/bin/sendgmail
    smtpServerOption = -sender=USERNAME@gmail.com
```
