# Choosing HTML snippets for detection

The HTML snippets configuration provides extra alerting and protection against fake versions of your company's SSO login page. There are two complementary settings that each provide a different benefit.


# SSO Page HTML (corp_html)
If you type your password and these snippets of HTML are present, then the LooksLikeGoogle bit in the alert is set to TRUE and the email to the security team contains a "Looks like phishing!" line. This helps you distinguish between alerts that are due to accidents and password reuse from alerts that are due to intentional phishing attacks.

This setting should have somewhat generic HTML from your SSO login page. They should be relatively unique, but do not have to be absolutely unique. Here are a few examples based on the main Google login page: 
```
One account. All of Google.
Sign in with your Google Account
<title>Sign in - Google Accounts
```
More examples are available in the [extension source code here](https://github.com/google/password-alert/blob/master/chrome/content_script.js#L126).



# SSO Page Core HTML (corp_html_tight)
This setting should have HTML snippets from your company's SSO login page that are very specific, such as actual HTML elements. If a user visits a page containing this HTML, but it is not your SSO page, the user will get an immediate alert. Because of this you should choose HTML  snippets that do not appear anywhere else on the Internet. Here is an example based on the main Google login page:
```
<input id="signIn" name="signIn" class="rc-button rc-button-submit" 'type="submit" value="Sign in
```
More examples are available in the [extension source code here](https://github.com/google/password-alert/blob/master/chrome/content_script.js#L140).



# Using multiple values for each setting
Both of these HTML settings allow you to specify multiple values. Each line is considered its own value for matching. For example, with this setting:
```
One account. All of Google.
Sign in with your Google Account
```
Any page that has either `Sign in with your Google Account` or `One account. All of Google.` will trigger the extra alert. Having both is not required.


# Example process for creating settings for your own SSO page
Let's walk through creating settings for your own SSO page. We'll use https://github.com/login as an example. First, look at the HTML source for the login page using right-click View page source. Now let's look for some things that indicate it's a Github page, but are not very specific. We'll use these values for the SSO Page HTML (corp_html) setting. Here are a few candidates:
```
© 2015 GitHub, Inc.
Password <a href="/password_reset">(forgot password)</a>
<span class="mega-octicon octicon-logo-github">
```

Now let's look for some examples that are very unique to the GitHub login page and should never appear anywhere else on the Internet. We'll use these values for the SSO Page Core HTML (corp_html_tight) setting. Here's a good candidate:
```
<title>Sign in · GitHub</title>
```

Doing a quick search for these different HTML snippets shows that they're relatively unique. Most importantly, the title HTML that we chose seems to only appear on pages that are copies of the GitHub login page.


# Other SSO Settings
Instructions on how to create values for the other SSO settings, such as SSO Form Selector (sso_form_selector), SSO Password Selector (sso_password_selector), SSO Server URL (sso_url), and SSO Username Selector (sso_username_selector) are described in the [Password Alert Deployment Guide section Configure SSO extension policies](https://docs.google.com/document/d/1bqbS6umRaNoRl2BZr4q9Q2YckmL-UHDcelkyPTy35AQ/preview#heading=h.8ovugfbimou0).
