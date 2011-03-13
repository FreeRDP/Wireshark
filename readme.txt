RDP Wireshark Dissector

In order to use this wireshark dissector for the RDP protocol, you will need to compile wireshark from the development sources.

There are two ways to add a dissector to wireshark: plug-in or built-in. Even though you could probably make the current dissector
a plug-in, I do not encourage to do it this way, as there is a major drawback: wireshark plug-ins aren't loaded in wireshark when
it is ran as root, for obvious security reasons. As you need to be root in order to capture packets, you won't be able to capture
and dissect the RDP protocol at the same time if you compile the dissector as a plug-in. Therefore, here are the instructions on how
to add this RDP dissector as built-in to wireshark, so you can use it while running wireshark as root.

Go to http://www.wireshark.org/develop.html and follow the instructions to get the latest wireshark development sources:
svn co http://anonsvn.wireshark.org/wireshark/trunk/ wireshark

Once you have the sources, instead a couple of development packages that you'll probably need, such as gtk-dev. Make sure that you have
SSL development libraries (GnuTLS, OpenSSL) installed, as wireshark will built without the SSL dissector if they aren't present when
running the configure script. As we are dependent on the SSL dissector for the RDP dissector, the SSL development libraries are mandatory.

Copy packet-rdp.c and packet-rdp.h to wireshark/epan/dissectors/ and add new entries in wireshark/epan/dissectors/Makefile.common:

Add this line right over the "packet-rdt.c" line (they're in alphabetical order):
	packet-rdp.c		\

Similarly add this line right over the "packet-rdt.h" line:
	packet-rdp.h	\

Now in the root of the wireshark folder, run autogen.sh if you haven't already, and run (or re-run) the configure script.
The configure script must be ran after Makefile.common has been modified, otherwise the new dissector won't get built.

When this is done and you've solved all dependencies the configure script may complain about, simply "make".
It takes a while the first time, but after that you're done :)

To test it out once it is built, use one of the sample packet captures that I've prepared:
http://www.awakecoding.com/downloads/rdp_sample_packet_capture.zip
http://www.awakecoding.com/downloads/rdp_sample_packet_capture_tls_without_nla.zip

Both archives contain a packet capture with a readme and the private key required to decrypt the TLS packets.
The dissector does not work with the RDP "legacy" encryption, only with RDP over TLS.

If you want to use the dissector to analyze your own packets, you will need to configure your server to use a self-signed certificate
with an exportable private key. The amount of effort required to do so varies a lot between versions of Windows Server. Some easy versions
are Windows Server 2003 SP1: http://thelazyadmin.com/blogs/thelazyadmin/archive/2007/01/26/Configure-RDP-over-SSL-with-SelfSSL.aspx
Otherwise you should give Windows Server 2008 _R2_ a try, and I really insist on the "R2" here. Windows Server 2008 (not R2) can create
a self-signed certificate for you, but it will mark the key as non-exportable by default, and there's no way around it. You can try
generating your own self-signed certificate to try to import it, but good luck on finding the almost non-existing information on the subject.
Windows Server 2008 R2 changed the default behavior to give you the option of NOT marking the private key as non-exportable. Once you get
a self-signed certificate with an exportable private key configured with your RDP server, it should be quite easy to figure out how to extract
the private key and convert it from pfx to pem format (OpenSSL can do it, just google it there are tons of websites that explain how).

Obviously the dissector is still in an early development stage and I put efforts on the packets that I need to take a closer look at. It is
still very useful and will probably save you a lot of time.


