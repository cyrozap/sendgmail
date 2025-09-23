# sendgmail

**sendgmail** is a tool that enables `git send-email` to send patches from a Gmail account without using SMTP.

This tool has been modified from its [original version](https://github.com/google/gmail-oauth2-tools/tree/578a11a744c37bd19c1c1b8d96061276dbf6f7f0/go/sendgmail).
This new version, inspired by [siketyan/sendgmail](https://github.com/siketyan/sendgmail), uses the Gmail [users.messages.send API](https://developers.google.com/gmail/api/reference/rest/v1/users.messages/send) to send the email instead of using SMTP.
This has the following advantages:

* The scope of the OAuth token can be limited to only sending emails.
  This avoids the potential danger created by generating a token with full Gmail permissions, which is necessary to send emails through Gmail using SMTP (when not using an app password, which grants even more permissions).

* Sent emails will always appear in the "Sent" folder in Gmail regardless of whether or not you CC yourself.
  In contrast, when a message is sent via SMTP, the message will not appear in the "Sent" folder unless you CC yourself.

> [!CAUTION]
> Unfortunately, it seems that sending patches via the Gmail API has some of the same limitations as sending via the Web UI.
> Namely, that some patches will get mangled by Gmail's insistence on line-wrapping certain long lines in plaintext emails.
> To avoid sending corrupted patches to public mailing lists, `sendgmail` automatically detects patches that are likely to be mangled by Gmail and will refuse to send them.


## Getting Started


### Step 1: Install `sendgmail`

```shell
go install github.com/cyrozap/sendgmail@latest
```

This will install `sendgmail` to `$GOPATH/bin/sendgmail`.


### Step 2: Create Google OAuth2 Client and Credentials

1. **Create a Google Cloud project**

   1. Visit the [Google Cloud console](https://console.cloud.google.com/).
   2. Open the project picker (to the right of the Google Cloud logo, or press *Ctrl+O*).
   3. Create a new project (name it e.g. `sendgmail`).
   4. In the **Notifications** window, wait for the project to finish being created, then click **Select Project** when the button appears.

2. **Enable the Gmail API**

   1. Click [this link](https://console.cloud.google.com/flows/enableapi?apiid=gmail.googleapis.com) to begin the process to enable the Gmail API for your `sendgmail` project.
   2. Click **Next**, then click **Enable**.

3. **Create the OAuth configuration**

   1. Open **Navigation menu (≡) > APIs & Services > OAuth consent screen**.
   2. Under where it says "Google Auth Platform not configured yet", click **Get started**.
   3. Set the **App name** to `sendgmail`.
   4. Set the **User support email** to your own email.
   5. Click **Next**.
   6. Set **Audience** to **External**, then click **Next**.
   7. Set the **Contact Information** email address to your own email, then click **Next**.
   8. Read and agree to the **Google API Services: User Data Policy**, then click **Continue** and then **Create**.

4. **Create the OAuth client and download credentials**

   1. Click **Create OAuth client**.
   2. Set **Application type** to **Web application**
   3. Set the **Name** to `sendgmail`, or leave it as-is.
   4. Under **Authorized redirect URIs**, click **Add URI**.
      - If you're using `sendgmail -setup` on the same computer that your browser is logged in to, set the URI to `http://localhost:8080/oauth2callback`.
        - This will configure `sendgmail -setup` to listen on that port for your browser to send it the authorization code.
        - You can change the port to another number if `sendgmail -setup` is not able to listen on port `8080` on your computer.
        - You can also set a loopback IP (like `127.0.0.1` or `[::1]`) as the host instead of `localhost`, if you prefer.
      - If you need to run `sendgmail -setup` on a different computer from the one that your browser is on, set the URI to `https://google.github.io/gmail-oauth2-tools/html/oauth2.dance.html`.
        - This will cause the authorization code to be displayed in your browser, and from there you'll have to copy and paste or manually enter the code into `sendgmail -setup`.
   5. Click **Create**.
   6. In the window that appears, click **Download JSON** to download the OAuth client credentials.
   7. Move the credentials JSON into the `sendgmail` configuration directory:

      ```shell
      CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/sendgmail"
      mkdir -p "$CONFIG_DIR"
      chmod 700 "$CONFIG_DIR"

      # Move the credentials file (must be named "config.json")
      mv path/to/credentials.json "$CONFIG_DIR"/config.json
      chmod 600 "$CONFIG_DIR"/config.json
      ```

5. **Enable the `gmail.send` API scope**

   1. Click **Data Access**, then click **Add or remove scopes**.
   2. Where it says **Enter property name or value**, type `gmail.send` and press the Enter/Return key.
   3. Check the checkbox just to the left of where it says "Gmail API" in the single row that should be visible.
   4. Click **Update**, then click **Save**.

6. **Add yourself as a test user**

   1. Click **Audience**.
   2. Under **Test users**, click **Add users**.
   3. Enter your own email, then click **Save**.


### Step 3: Generate OAuth2 Token

Run the following command to perform the OAuth2 authorization:

```shell
# Replace with your Gmail address
$GOPATH/bin/sendgmail -sender=USERNAME@gmail.com -setup
```

Follow the remaining steps in your browser.
If you set the **Authorized redirect URI** to a local URL, then at the end of the process the token will automatically be sent to `sendgmail`.
If you instead set it to `.../oauth2.dance.html`, then you'll have to copy the code and paste it where prompted by `sendgmail`.


## Usage with Git

> [!NOTE]
> This assumes you've completed the [OAuth2 setup](#step-2-create-google-oauth2-client-and-credentials).

Add the following section to `.gitconfig` in your home directory:

```
[sendemail]
    smtpServer = /full/path/to/sendgmail  # From $GOPATH/bin/sendgmail or custom path
    smtpServerOption = -sender=USERNAME@gmail.com
```
