# Overview

As of MWC713 v2.1.3, a new broker known as mwcmqs is supported. This broker is meant to eventually replace the old
mwcbox code that was used for messaging. The backend that supports this is in the mwcmqs project here:
https://github.com/mwcproject/mwcmqs.
The benefits of this new "mwcmqs" broker is that it supports SSL on windows (which is not supported in the mwcbox code) and
it also currently has some logic to tell you if the message was received by the recipient. The design is also more lightweight
and should be easier to scale.

# Commands needed in mwc713

Your mwc713 instance will use the same address for mwcmqs as it does for mwcmq. The only difference is that it has a different
label. So, for instance, if your mwcmqs address is mwcmq://xmifskXS7CmzhCHxVHvNhJsSLdFx1aipW6MJ94kdpuKEiaHPRwEA, your mwcmqs
address will be mwcmqs://xmifskXS7CmzhCHxVHvNhJsSLdFx1aipW6MJ94kdpuKEiaHPRwEA. If you are not using the default mwcmqs domain (mqs.mwc.mw), you can specify it like this mwcmqs://xmifskXS7CmzhCHxVHvNhJsSLdFx1aipW6MJ94kdpuKEiaHPRwEA@example.com: This address format will work with send and
automatically know what to do if you use the 'mwcmqs' label. The default label in this version will remain mwcmq, but in
future versions, it can be expected to change to the newer protocol. In addition to using this label for sends, you will need
to start the mwcmqs listener. To do this, you can use the listen command with the -s option:

wallet713> listen -s

In addition, you can stop the listener with the stop -s command:

wallet713> stop -s

That is really all there is to it.

# Running your own mwcmqs server

Just like mwcbox and mwcmq, you can run your own mwcmqs instance and create a new domain. The project is mvn based, so all
that needs to be done is to build it using "mvn install" and then start the jetty webserver: "cd jetty", "./start.sh". You
will need to enable ssl by either installing a certificate into jetty or by using a reverse proxy that supports certificates
like nginx. The default domain for mwcmqs is mqs.mwc.mw which we maintain. But just like mwcbox, any new domain can be used
and configured into mwc713 using the "mwcmqs_domain" domain configuration parameter. Also, the mwcmqs_port variable is
available, with a default of 443. Currently federation is not supported, but it is definitely something that will be on our
roapdmap.

# TODO

- TxProofs
- Federation
- More robust messaging about status of other connected parties
