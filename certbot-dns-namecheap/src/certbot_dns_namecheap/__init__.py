"""
The `~certbot_dns_namecheap.dns_namecheap` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Namecheap API.

.. note::
   The plugin is not installed by default.

.. important::
   Namecheap's API has no means to update a single record - the setHosts call
   rewrites all records at once.  This plugin therefore reads the zone, adds or
   removes the challenge record, and writes every record back.

   To add some protection because of this operation, the plugin archives each
   zone as raw XML before rewriting it (see ``--dns-namecheap-zone-backup-dir``),
   serialises rewrites of the same zone with a lock file, refuses to touch a zone
   holding record types the API cannot write back (see
   ``--dns-namecheap-allow-unwritable-types``), and reads the zone back afterwards
   to confirm the result. Avoid editing a domain's records in the Namecheap web UI
   while Certbot is running: the API offers no way to detect a concurrent change,
   so one of the two edits will be lost.

Named Arguments
---------------

===============================================  =====================================
``--dns-namecheap-credentials``                  Namecheap credentials_ INI file.
                                                 (Required)
``--dns-namecheap-propagation-seconds``          The number of seconds to wait for
                                                 DNS to propagate before asking the
                                                 ACME server to verify the DNS
                                                 record.
                                                 (Default: 60)
``--dns-namecheap-zone-backup-dir``              Directory in which each zone is
                                                 archived before it is rewritten.
                                                 (Default: ``namecheap-zone-backups``
                                                 inside Certbot's configuration
                                                 directory)
``--dns-namecheap-lock-dir``                     Directory holding the per-zone lock
                                                 files that serialise rewrites.
                                                 (Default: a per-uid directory under
                                                 the system temporary directory)
``--dns-namecheap-allow-unwritable-types``       Rewrite a zone even when it holds
                                                 record types the API cannot write
                                                 back, such as ``SRV``. Those records
                                                 will be destroyed.
                                                 (Default: off)
===============================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing Namecheap API
credentials, obtained from the `API Access page
<https://ap.www.namecheap.com/settings/tools/apiaccess/>`_ of your Namecheap
account's profile.

API access must be enabled on the account, and the public IP address of the
machine running Certbot must be added to Namecheap's API whitelist. Requests
from any other address are rejected.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Namecheap API credentials used by Certbot
   dns_namecheap_api_user = namecheap-account-user
   dns_namecheap_api_key = 0123456789abcdef0123456789abcdef
   dns_namecheap_client_ip = 192.168.0.1

   # Optional. Defaults to dns_namecheap_api_user; set it when the API user
   # differs from the account whose domains are being managed.
   # dns_namecheap_username = namecheap-account-user

   # Optional. Set to true to talk to Namecheap's sandbox API instead of
   # production, for testing.
   # dns_namecheap_sandbox = false

The path to this file can be provided interactively or using the
``--dns-namecheap-credentials`` command-line argument. Certbot records the
path to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Namecheap account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-namecheap \\
     --dns-namecheap-credentials ~/.secrets/certbot/namecheap.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-namecheap \\
     --dns-namecheap-credentials ~/.secrets/certbot/namecheap.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a wildcard certificate for ``*.example.com``

   certbot certonly \\
     --dns-namecheap \\
     --dns-namecheap-credentials ~/.secrets/certbot/namecheap.ini \\
     -d example.com \\
     -d '*.example.com'

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 120 seconds
             for DNS propagation

   certbot certonly \\
     --dns-namecheap \\
     --dns-namecheap-credentials ~/.secrets/certbot/namecheap.ini \\
     --dns-namecheap-propagation-seconds 120 \\
     -d example.com

.. code-block:: bash
   :caption: To keep the zone backups somewhere other than Certbot's
             configuration directory

   certbot certonly \\
     --dns-namecheap \\
     --dns-namecheap-credentials ~/.secrets/certbot/namecheap.ini \\
     --dns-namecheap-zone-backup-dir /var/backups/namecheap \\
     -d example.com

"""
