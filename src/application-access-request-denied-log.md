# Application Access Request Denied Log

~~~admonish info
This document provides the screenshots of the corresponding log entries from a
known denied login attempt.
~~~

Medizues Login Screen (with invalid username and password):

![](application-access-request-denied-log/screenshot-1.png)

Errors for the event are recorded in the `nginx/access.log` CloudWatch logs:

![](application-access-request-denied-log/screenshot-2.png)

And further detail for the same events are included in the `pm2` logs:

![](application-access-request-denied-log/screenshot-3.png)
