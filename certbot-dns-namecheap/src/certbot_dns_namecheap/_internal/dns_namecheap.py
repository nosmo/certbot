"""DNS Authenticator for Namecheap."""
import contextlib
import logging
import os
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any
from typing import Callable
from typing import cast
from typing import Iterator
from typing import Optional

from certbot import achallenges
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

PROD_URL = 'https://api.namecheap.com/xml.response'
SANDBOX_URL = 'https://api.sandbox.namecheap.com/xml.response'

# getList is paged; 100 is the documented maximum page size.
DOMAIN_PAGE_SIZE = 100

# The RecordType values namecheap.domains.dns.setHosts documents. Because
# setHosts rewrites the whole zone, a record whose type is not in this set
# cannot be written back and would be silently destroyed by any update --
# notably SRV, which Namecheap's web UI offers but setHosts does not accept.
SETHOSTS_TYPES = frozenset([
    'A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'MXE', 'NS', 'TXT', 'URL', 'URL301', 'FRAME',
])


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Namecheap

    This Authenticator uses the Namecheap API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using Namecheap for DNS).')
    # Namecheap accepts a TTL between 60 and 60000 seconds.
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Namecheap credentials INI file.')
        add('zone-backup-dir',
            help='Directory in which to archive each zone before it is rewritten. '
                 'Defaults to a "namecheap-zone-backups" directory inside Certbot\'s '
                 'configuration directory.')
        add('lock-dir',
            help='Directory holding the per-zone lock files used to serialise zone '
                 'rewrites. Defaults to a per-uid directory under the system temporary '
                 'directory.')
        add('allow-unwritable-types', action='store_true', default=False,
            help='Update a zone even when it contains record types that the Namecheap '
                 'setHosts API cannot write back (for example SRV). Those records WILL '
                 'be destroyed. Off by default.')

    def more_info(self) -> str:
        return ('This plugin configures a DNS TXT record to respond to a dns-01 challenge using '
                'the Namecheap API.')

    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        delay = self.conf('propagation-seconds')
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by '
            '--dns-namecheap. Ensure the above domains are registered with Namecheap and use '
            'Namecheap BasicDNS or PremiumDNS, that dns_namecheap_client_ip holds this '
            'machine\'s public address, and that the address is whitelisted for API access. '
            'You may also need to increase --dns-namecheap-propagation-seconds (currently '
            '{secs} second{suffix}).'.format(secs=delay, suffix='s' if delay != 1 else '')
        )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Namecheap credentials INI file',
            {
                'api-user': 'API user for the Namecheap account',
                'api-key': 'API key for the Namecheap account',
                'client-ip': 'the public IP address of this machine, whitelisted for API '
                             'access in the Namecheap account',
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_namecheap_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_namecheap_client().del_txt_record(domain, validation_name, validation)

    def _get_namecheap_client(self) -> "_NamecheapClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")

        api_user = cast(str, self.credentials.conf('api-user'))
        backup_dir = self.conf('zone-backup-dir') or os.path.join(
            self.config.config_dir, 'namecheap-zone-backups')

        return _NamecheapClient(
            api_user,
            cast(str, self.credentials.conf('api-key')),
            self.credentials.conf('username') or api_user,
            cast(str, self.credentials.conf('client-ip')),
            sandbox=_is_true(self.credentials.conf('sandbox')),
            backup_dir=backup_dir,
            lock_dir=self.conf('lock-dir') or _default_lock_dir(),
            allow_unwritable_types=self.conf('allow-unwritable-types'),
        )


def _is_true(value: Optional[str]) -> bool:
    return (value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def _default_lock_dir() -> str:
    # Per-uid so that unprivileged runs cannot collide on a lock file they are
    # not permitted to open.
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    return os.path.join(tempfile.gettempdir(), 'certbot-namecheap-locks-%d' % uid)


def _strip_ns(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


class _NamecheapClient:
    """
    Encapsulates all communication with the Namecheap API.

    Namecheap has no call that edits a single DNS record. The only way to change
    one is namecheap.domains.dns.setHosts, which replaces the *entire* host
    record set for a domain: every record omitted from the call is deleted. So
    each change here is a read-modify-write -- getHosts, edit in memory,
    setHosts -- which is guarded four ways:

    * the whole sequence runs under an exclusive per-zone lock file, because two
      overlapping rewrites would silently discard each other's record (the API
      offers no version token with which to detect that);
    * the zone as read is archived as raw XML before anything is written;
    * the write is refused if the zone holds a record type setHosts cannot
      express, since rewriting would destroy those records;
    * the zone is read back afterwards and compared against what was sent.
    """

    def __init__(self, api_user: str, api_key: str, username: str, client_ip: str,
                 sandbox: bool = False, backup_dir: Optional[str] = None,
                 lock_dir: Optional[str] = None,
                 allow_unwritable_types: bool = False) -> None:
        self.url = SANDBOX_URL if sandbox else PROD_URL
        self.globals = {
            'ApiUser': api_user,
            'ApiKey': api_key,
            'UserName': username,
            'ClientIp': client_ip,
        }
        self.backup_dir = backup_dir
        self.lock_dir = lock_dir or _default_lock_dir()
        self.allow_unwritable_types = allow_unwritable_types
        self.last_raw = b''

    def add_txt_record(self, domain_name: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        The record is added alongside any records already present, including
        other TXT records with the same name: a wildcard certificate produces
        two challenges for one name, and both values must be published at once.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL.
        :raises certbot.errors.PluginError: if an error occurs communicating with the Namecheap API
        """
        sld, tld = self._find_domain(domain_name)
        host = self._compute_record_name(record_name, '%s.%s' % (sld, tld))
        new = {
            'Name': host,
            'Type': 'TXT',
            'Address': record_content,
            'MXPref': '10',
            'TTL': str(record_ttl),
        }

        def add(records: list[dict[str, str]]) -> list[dict[str, str]]:
            if any(_same_txt(rec, new) for rec in records):
                logger.debug('TXT record %s already present, leaving the zone alone', host)
                return records
            return records + [new]

        self._modify_zone(sld, tld, add, expect_existing=True)
        logger.debug('Successfully added TXT record %s for %s.%s', host, sld, tld)

    def del_txt_record(self, domain_name: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """
        try:
            sld, tld = self._find_domain(domain_name)
        except errors.PluginError as e:
            logger.debug('Error finding domain using the Namecheap API: %s', e)
            return

        host = self._compute_record_name(record_name, '%s.%s' % (sld, tld))
        target = {'Name': host, 'Type': 'TXT', 'Address': record_content}

        def remove(records: list[dict[str, str]]) -> list[dict[str, str]]:
            return [rec for rec in records if not _same_txt(rec, target)]

        try:
            self._modify_zone(sld, tld, remove)
            logger.debug('Successfully removed TXT record %s for %s.%s', host, sld, tld)
        except errors.PluginError as e:
            logger.warning('Error deleting TXT record %s using the Namecheap API: %s', host, e)

    def _modify_zone(self, sld: str, tld: str,
                     mutate: Callable[[list[dict[str, str]]], list[dict[str, str]]],
                     expect_existing: bool = False) -> None:
        """Read the zone, apply `mutate` to its records, and write it back.

        The lock is held across the read, the write and the read-back, so a
        concurrent run on this host cannot interleave with any part of it.

        :param bool expect_existing: whether an empty zone is a surprise worth
            warning about, as it is when adding a record to a zone that should
            already hold others.
        """
        with self._zone_lock(sld, tld):
            existing, email_type, raw = self._get_hosts(sld, tld)

            if expect_existing and not existing:
                # Not fatal: a zone really can be empty. But the rewrite below
                # is about to define the whole zone from this reading of it, so
                # say so rather than quietly publishing a one-record zone.
                logger.warning('The Namecheap API reports no existing host records for %s.%s. '
                               'The zone will be rewritten to contain only the challenge '
                               'record.', sld, tld)

            unwritable = sorted({rec['Type'] for rec in existing
                                 if rec['Type'] not in SETHOSTS_TYPES})
            if unwritable:
                message = ('{0}.{1} contains record type(s) that the Namecheap setHosts API '
                           'cannot write back: {2}. Updating the zone would destroy those '
                           'records.'.format(sld, tld, ', '.join(unwritable)))
                if not self.allow_unwritable_types:
                    raise errors.PluginError(
                        message + ' Remove them, or pass --dns-namecheap-allow-unwritable-types '
                                  'to accept the loss.')
                logger.warning('%s Continuing because '
                               '--dns-namecheap-allow-unwritable-types was given.', message)

            updated = mutate(list(existing))
            if _record_key_set(updated) == _record_key_set(existing):
                logger.debug('Zone %s.%s already in the desired state', sld, tld)
                return

            self._backup_zone(raw, sld, tld)
            self._set_hosts(sld, tld, updated, email_type)
            self._verify_zone(sld, tld, updated)

    @contextlib.contextmanager
    def _zone_lock(self, sld: str, tld: str) -> Iterator[None]:
        """Hold an exclusive lock for one zone.

        This only serialises processes on this host. A rewrite from another
        machine, or an edit in the Namecheap web UI, is still unserialised --
        which is what the read-back in :meth:`_verify_zone` is there to catch.
        """
        try:
            import fcntl
        except ImportError:  # pragma: no cover
            logger.warning('File locking is unavailable on this platform; concurrent zone '
                           'updates cannot be serialised.')
            yield
            return

        try:
            os.makedirs(self.lock_dir, exist_ok=True)
        except OSError as e:
            raise errors.PluginError(
                'Could not create the lock directory {0}: {1}'.format(self.lock_dir, e))

        path = os.path.join(self.lock_dir, '%s.%s.lock' % (sld, tld))
        # Opened, never unlinked: unlinking it would let another process lock a
        # deleted inode while this one still holds the original.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            waited = False
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if not waited:
                        logger.info('Waiting for another process to finish updating %s.%s ...',
                                    sld, tld)
                        waited = True
                    time.sleep(0.25)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _backup_zone(self, raw: bytes, sld: str, tld: str) -> None:
        """Archive the getHosts reply verbatim before overwriting the zone."""
        if not self.backup_dir:  # pragma: no cover
            return
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
            base = os.path.join(self.backup_dir, '%s.%s-%s.xml' % (sld, tld, stamp))
            for attempt in range(100):
                candidate = base if attempt == 0 else '%s.%d' % (base, attempt)
                try:
                    # Exclusive create, so a second run in the same second cannot
                    # overwrite the first one's backup.
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    continue
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(raw)
                logger.debug('Archived %s.%s to %s before rewriting it', sld, tld, candidate)
                return
            raise OSError('could not create a backup file in %s' % self.backup_dir)
        except OSError as e:
            # Fail closed: without an archive of the current zone, do not rewrite it.
            raise errors.PluginError(
                'Could not archive the current records for {0}.{1} to {2}: {3}. Refusing to '
                'rewrite the zone without a backup.'.format(sld, tld, self.backup_dir, e))

    def _verify_zone(self, sld: str, tld: str, sent: list[dict[str, str]]) -> None:
        """Read the zone back and warn about anything that did not land as sent."""
        try:
            found, _, _ = self._get_hosts(sld, tld)
        except errors.PluginError as e:  # pragma: no cover
            logger.warning('Could not read %s.%s back to verify the update: %s', sld, tld, e)
            return

        sent_keys = _record_key_set(sent)
        found_keys = _record_key_set(found)

        for key in sorted(sent_keys - found_keys):
            logger.warning('Record %s %s %s is missing after updating %s.%s; compare the zone '
                           'against the backup in %s', key[0], key[1], key[2], sld, tld,
                           self.backup_dir)
        for key in sorted(found_keys - sent_keys):
            logger.warning('Unexpected record %s %s %s present after updating %s.%s',
                           key[0], key[1], key[2], sld, tld)

    def _find_domain(self, domain_name: str) -> tuple[str, str]:
        """
        Find the SLD and TLD of the Namecheap domain covering a given name.

        :param str domain_name: The domain name for which to find the base domain.
        :returns: The (SLD, TLD) pair, as setHosts and getHosts want them.
        :raises certbot.errors.PluginError: if no matching domain is found.
        """
        guesses = dns_common.base_domain_name_guesses(domain_name)
        domains = self._list_domains()

        for guess in guesses:
            if guess in domains:
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                sld, _, tld = guess.partition('.')
                return sld, tld

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, guesses))

    def _list_domains(self) -> set[str]:
        """Every domain on the account, lowercased. getList is paged."""
        names: set[str] = set()
        page = 1
        while True:
            response = self._call('namecheap.domains.getList',
                                  {'ListType': 'ALL', 'Page': str(page),
                                   'PageSize': str(DOMAIN_PAGE_SIZE)})
            before = len(names)
            names.update(
                (element.get('Name') or '').lower()
                for element in response.iter()
                if _strip_ns(element.tag) == 'Domain'
            )
            if len(names) == before:
                # An empty or wholly duplicate page: nothing further to collect,
                # whatever TotalItems claims.
                return names

            total_element = next((element for element in response.iter()
                                  if _strip_ns(element.tag) == 'TotalItems'), None)
            try:
                total = int((total_element.text or '0').strip())
            except (AttributeError, ValueError):
                return names
            if len(names) >= total:
                return names
            page += 1

    def _get_hosts(self, sld: str, tld: str) -> tuple[list[dict[str, str]], Optional[str], bytes]:
        """Return the zone's records, its EmailType, and the unparsed reply."""
        response = self._call('namecheap.domains.dns.getHosts', {'SLD': sld, 'TLD': tld})
        raw = self.last_raw

        result = next((element for element in response
                       if _strip_ns(element.tag) == 'DomainDNSGetHostsResult'), None)
        if result is None:
            raise errors.PluginError(
                'No host records returned for {0}.{1} by the Namecheap API.'.format(sld, tld))
        if (result.get('IsUsingOurDNS') or '').lower() == 'false':
            raise errors.PluginError(
                '{0}.{1} is not using Namecheap DNS, so its host records cannot be edited. '
                'Point the domain at Namecheap BasicDNS or PremiumDNS, or use the Certbot '
                'plugin for its actual DNS provider.'.format(sld, tld))

        records = [
            {
                'Name': element.get('Name') or '@',
                'Type': element.get('Type') or '',
                'Address': element.get('Address') or '',
                'MXPref': element.get('MXPref') or '10',
                'TTL': element.get('TTL') or '1800',
            }
            for element in result
            if _strip_ns(element.tag) == 'Host'
        ]
        # EmailType is carried across the rewrite so that updating a record does
        # not reset the domain's mail configuration. It is absent from the
        # setHosts parameter table in Namecheap's documentation, but getHosts
        # returns it and setHosts accepts it.
        return records, result.get('EmailType'), raw

    def _set_hosts(self, sld: str, tld: str, records: list[dict[str, str]],
                   email_type: Optional[str]) -> None:
        """Replace the zone's entire record set."""
        params = {'SLD': sld, 'TLD': tld}
        for i, record in enumerate(records, start=1):
            params['HostName%d' % i] = record['Name']
            params['RecordType%d' % i] = record['Type']
            params['Address%d' % i] = record['Address']
            params['TTL%d' % i] = record['TTL']
            if record['Type'] in ('MX', 'MXE'):
                params['MXPref%d' % i] = record['MXPref']
        if email_type:
            params['EmailType'] = email_type

        response = self._call('namecheap.domains.dns.setHosts', params)
        result = next((element for element in response
                       if _strip_ns(element.tag) == 'DomainDNSSetHostsResult'), None)
        if result is None or (result.get('IsSuccess') or '').lower() != 'true':
            raise errors.PluginError(
                'The Namecheap API did not confirm the update to {0}.{1}.'.format(sld, tld))

    def _call(self, command: str, params: dict[str, str]) -> ET.Element:
        """POST one command and return its CommandResponse element.

        The unparsed reply is kept in ``self.last_raw`` so that a zone can be
        archived exactly as the API returned it.
        """
        body = dict(self.globals, Command=command, **params)
        request = urllib.request.Request(
            self.url,
            data=urllib.parse.urlencode(body).encode(),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except OSError as e:
            # urllib's URLError and HTTPError are both OSError subclasses.
            raise errors.PluginError(
                'Error communicating with the Namecheap API: {0}'.format(e))

        self.last_raw = raw

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            raise errors.PluginError(
                'Could not parse the Namecheap API response to {0}: {1}'.format(command, e))

        if (root.get('Status') or '').lower() != 'ok':
            errs = ['{0}: {1}'.format(element.get('Number'), (element.text or '').strip())
                    for element in root.iter() if _strip_ns(element.tag) == 'Error']
            hint = ''
            if any('IP' in err or 'API' in err for err in errs):
                hint = (' (is dns_namecheap_client_ip this machine\'s public address, and is '
                        'that address whitelisted for API access in the Namecheap account?)')
            raise errors.PluginError('Error from the Namecheap API calling {0}: {1}{2}'
                                     .format(command, '; '.join(errs) or 'unknown error', hint))

        command_response = next((child for child in root
                                 if _strip_ns(child.tag) == 'CommandResponse'), None)
        if command_response is None:
            raise errors.PluginError(
                'The Namecheap API returned no response body for {0}.'.format(command))
        return command_response

    @staticmethod
    def _compute_record_name(full_record_name: str, base_domain: str) -> str:
        # Namecheap wants the host relative to the domain, with '@' for the apex.
        if full_record_name.rstrip('.').lower() == base_domain.lower():
            return '@'
        return full_record_name.rpartition('.' + base_domain)[0] or full_record_name


def _same_txt(record: dict[str, str], other: dict[str, str]) -> bool:
    """Whether two records are the same TXT name/value pair."""
    return (record['Type'] == 'TXT' and other['Type'] == 'TXT'
            and record['Name'] == other['Name']
            and record['Address'] == other['Address'])


def _record_key_set(records: list[dict[str, str]]) -> set[tuple[str, str, str]]:
    """Identify records by name, type and value, ignoring order and TTL."""
    return {(record['Name'], record['Type'], record['Address']) for record in records}
