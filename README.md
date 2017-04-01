# fritz
After stumbling upon a per implementation of the history i've digged out the article from german computer magazine c't where access to thefritz ox was schon be using powershell scripting. While the article gave me some insight in the soapish communication protocol TR64 I didn't like the powershell implementaion at all. It didn't use newer powershell features (> v3.0) like 'Invoke-RestMethod'.

This repo contains my take on the implementation of TR64 with powershell. It is by far not complete and provides the following features:

* Retrieve the (unsecured) device information
* Retrieve (and cache for reuse) the security port for authenticated https communication with the fritz box
* Ask for the user credentials and cache the credentials for reuse
* Retrieve the phone book
* Retrieve the call list

## Precondition: Accept the firtz Box Self Signed Certificates
