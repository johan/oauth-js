This is JavaScript software for implementing an OAuth consumer.

Authors:
John Kristian

IMPORTANT NOTE
==============
This library isn't as useful as you think it's going to be.

OAuth is based around allowing tools and websites to talk to each other.
However, JavaScript running in web browsers is nearly always hampered by
security restrictions which prevent code running on one website from
accessing data stored or served on another.

Before you start hacking, make sure you understand the limitations posed
by cross-domain XMLHttpRequest.

WITH THAT SAID...
=================
There are an increasing number of platforms which use JavaScript as
their language, but enable the programmer to access remote sites.
Examples include Google Gadgets, and Microsoft Vista Sidebar. For those
platforms, this library should come in handy.
