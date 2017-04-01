# fritz

After stumbling upon a perl implementation of TR64 I've digged out an article from german computer magazine c't where access to the fritz box was shown by using powershell scripting. While the article gave me some insight in the soapish communication protocol TR64. I didn't like the powershell implementation. It didn't use newer powershell features (> v3.0) like 'Invoke-RestMethod'.

This repo contains my take on the implementation of TR64 with powershell. It is by far not complete and provides the following features only:

* Retrieve the (unsecured) device information
* Retrieve (and cache for reuse) the security port for authenticated https communication with the fritz box
* Ask for the user credentials and cache the credentials for reuse
* Retrieve the phone book
* Retrieve the call list

This repo might be an interesting read for anybody on the same powershell journey and if you want to know more aboout I figured out what to call and how, please feel free to contact me.

## Precondition: Accept the Fritz Box Self Signed Certificates

SSL communication with the fritz box over the secure port uses a self signed certificate. This certificate is rejected by the .Net frameworks WebClient class by default. To help with this I've included my Web security helper script 'Intialize-WebClientSecurity.ps1' in this repo. Call this script first before you use the fritz modules functions.

```
Initialize-WebClientSecurity -AcceptAllCertificates
```
