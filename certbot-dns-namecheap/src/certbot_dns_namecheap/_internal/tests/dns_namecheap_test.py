"""Tests for certbot_dns_namecheap._internal.dns_namecheap."""

import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_USER = 'an-api-user'
API_KEY = 'an-api-key'
CLIENT_IP = '203.0.113.4'


def api_response(body):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">'
            '<Errors />' + body + '</ApiResponse>').encode()


def domain_list(names, total=None):
    domains = ''.join('<Domain ID="1" Name="{0}" IsOurDNS="true" />'.format(name)
                      for name in names)
    return api_response(
        '<CommandResponse Type="namecheap.domains.getList">'
        '<DomainGetListResult>{0}</DomainGetListResult>'
        '<Paging><TotalItems>{1}</TotalItems><CurrentPage>1</CurrentPage>'
        '<PageSize>100</PageSize></Paging>'
        '</CommandResponse>'.format(domains, total if total is not None else len(names)))


def host_list(hosts, is_our_dns='true', email_type='MX'):
    records = ''.join(
        '<Host HostId="{0}" Name="{1}" Type="{2}" Address="{3}" MXPref="10" TTL="{4}" />'
        .format(i, name, type_, address, ttl)
        for i, (name, type_, address, ttl) in enumerate(hosts))
    return api_response(
        '<CommandResponse Type="namecheap.domains.dns.getHosts">'
        '<DomainDNSGetHostsResult Domain="{0}" EmailType="{1}" IsUsingOurDNS="{2}">{3}'
        '</DomainDNSGetHostsResult></CommandResponse>'
        .format(DOMAIN, email_type, is_our_dns, records))


SET_HOSTS_OK = api_response(
    '<CommandResponse Type="namecheap.domains.dns.setHosts">'
    '<DomainDNSSetHostsResult Domain="{0}" IsSuccess="true" />'
    '</CommandResponse>'.format(DOMAIN))

SET_HOSTS_FAILED = api_response(
    '<CommandResponse Type="namecheap.domains.dns.setHosts">'
    '<DomainDNSSetHostsResult Domain="{0}" IsSuccess="false" />'
    '</CommandResponse>'.format(DOMAIN))

API_ERROR = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR">'
             '<Errors><Error Number="2019166">Domain not found</Error></Errors>'
             '</ApiResponse>').encode()

EXISTING = [('@', 'A', '198.51.100.1', '1800'),
            ('www', 'CNAME', 'example.invalid.', '1800')]


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_namecheap._internal.dns_namecheap import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"namecheap_api_user": API_USER,
                               "namecheap_api_key": API_KEY,
                               "namecheap_client_ip": CLIENT_IP}, path)

        self.config = mock.MagicMock(namecheap_credentials=path,
                                     namecheap_propagation_seconds=0,  # don't wait during tests
                                     namecheap_zone_backup_dir=os.path.join(self.tempdir, 'bk'),
                                     namecheap_lock_dir=os.path.join(self.tempdir, 'lk'),
                                     namecheap_allow_unwritable_types=False,
                                     config_dir=self.tempdir)

        self.auth = Authenticator(self.config, "namecheap")

        self.mock_client = mock.MagicMock()
        # _get_namecheap_client | pylint: disable=protected-access
        setattr(self.auth, '_get_namecheap_client',
                mock.MagicMock(return_value=self.mock_client))

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, 60)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_client_uses_credentials_and_defaults(self):
        # _get_namecheap_client is mocked above; test the real one.
        from certbot_dns_namecheap._internal.dns_namecheap import Authenticator

        auth = Authenticator(self.config, "namecheap")
        auth._setup_credentials()
        client = auth._get_namecheap_client()

        assert client.globals['ApiUser'] == API_USER
        assert client.globals['ApiKey'] == API_KEY
        assert client.globals['ClientIp'] == CLIENT_IP
        # username defaults to the API user
        assert client.globals['UserName'] == API_USER
        assert 'sandbox' not in client.url
        assert client.allow_unwritable_types is False

    def test_backup_dir_defaults_into_config_dir(self):
        from certbot_dns_namecheap._internal.dns_namecheap import Authenticator

        self.config.namecheap_zone_backup_dir = None
        auth = Authenticator(self.config, "namecheap")
        auth._setup_credentials()

        assert auth._get_namecheap_client().backup_dir == os.path.join(
            self.tempdir, 'namecheap-zone-backups')

    def test_auth_hint(self):
        assert 'whitelisted' in self.auth.auth_hint([])


class NamecheapClientTest(unittest.TestCase):

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"
    record_ttl = 60

    def setUp(self):
        from certbot_dns_namecheap._internal.dns_namecheap import _NamecheapClient

        self.tempdir = os.path.join(os.path.realpath('/tmp'),
                                    'certbot-dns-namecheap-test-%d' % os.getpid())
        self.client = _NamecheapClient(API_USER, API_KEY, API_USER, CLIENT_IP,
                                       backup_dir=os.path.join(self.tempdir, 'bk'),
                                       lock_dir=os.path.join(self.tempdir, 'lk'))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def _mock_api(self, replies):
        """Serve `replies` in order; record the params of every request."""
        self.requests = []

        def urlopen(request, timeout=None):
            import urllib.parse
            self.requests.append(dict(urllib.parse.parse_qsl(request.data.decode())))
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return mock.MagicMock(
                __enter__=mock.MagicMock(return_value=mock.MagicMock(
                    read=mock.MagicMock(return_value=reply))),
                __exit__=mock.MagicMock(return_value=False))

        return mock.patch('urllib.request.urlopen', side_effect=urlopen)

    def _sent_records(self, request):
        """The record set carried by a setHosts request, as a set of triples."""
        records = set()
        i = 1
        while 'HostName%d' % i in request:
            records.add((request['HostName%d' % i], request['RecordType%d' % i],
                         request['Address%d' % i]))
            i += 1
        return records

    def test_add_txt_record(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING), SET_HOSTS_OK,
                             host_list(EXISTING + [(self.record_prefix, 'TXT',
                                                    self.record_content, '60')])]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        set_hosts = self.requests[2]
        assert set_hosts['Command'] == 'namecheap.domains.dns.setHosts'
        assert set_hosts['SLD'] == DOMAIN.partition('.')[0]
        assert set_hosts['TLD'] == DOMAIN.partition('.')[2]
        # The challenge record is added...
        assert (self.record_prefix, 'TXT', self.record_content) in self._sent_records(set_hosts)
        # ...and every pre-existing record is written back with it.
        for name, type_, address, _ in EXISTING:
            assert (name, type_, address) in self._sent_records(set_hosts)
        # EmailType is carried across so the rewrite does not reset mail settings.
        assert set_hosts['EmailType'] == 'MX'

    def test_add_txt_record_appends_to_existing_challenge_record(self):
        """A wildcard cert publishes two TXT values at one name; keep both."""
        first = (self.record_prefix, 'TXT', 'first-value', '60')
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING + [first]), SET_HOSTS_OK,
                             host_list(EXISTING + [first, (self.record_prefix, 'TXT',
                                                           self.record_content, '60')])]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        sent = self._sent_records(self.requests[2])
        assert (self.record_prefix, 'TXT', 'first-value') in sent
        assert (self.record_prefix, 'TXT', self.record_content) in sent

    def test_add_txt_record_already_present_is_a_no_op(self):
        present = (self.record_prefix, 'TXT', self.record_content, '60')
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING + [present])]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        assert [r['Command'] for r in self.requests] == ['namecheap.domains.getList',
                                                         'namecheap.domains.dns.getHosts']

    def test_add_txt_record_writes_backup_before_setting_hosts(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING), SET_HOSTS_OK,
                             host_list(EXISTING + [(self.record_prefix, 'TXT',
                                                    self.record_content, '60')])]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        backups = os.listdir(self.client.backup_dir)
        assert len(backups) == 1
        with open(os.path.join(self.client.backup_dir, backups[0]), 'rb') as handle:
            saved = handle.read()
        # The archive is the pre-write zone, verbatim.
        assert saved == host_list(EXISTING)

    def test_add_txt_record_refuses_zone_with_unwritable_types(self):
        zone = EXISTING + [('_sip._tcp', 'SRV', '0 5 5060 sip.example.invalid.', '1800')]
        with self._mock_api([domain_list([DOMAIN]), host_list(zone)]):
            with pytest.raises(errors.PluginError, match='SRV'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

        # Nothing was written.
        assert 'namecheap.domains.dns.setHosts' not in [r['Command'] for r in self.requests]
        assert not os.path.isdir(self.client.backup_dir)

    def test_add_txt_record_unwritable_types_override(self):
        zone = EXISTING + [('_sip._tcp', 'SRV', '0 5 5060 sip.example.invalid.', '1800')]
        self.client.allow_unwritable_types = True
        with self._mock_api([domain_list([DOMAIN]), host_list(zone), SET_HOSTS_OK,
                             host_list(zone + [(self.record_prefix, 'TXT',
                                                self.record_content, '60')])]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        assert 'namecheap.domains.dns.setHosts' in [r['Command'] for r in self.requests]

    def test_add_txt_record_apex(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING), SET_HOSTS_OK,
                             host_list(EXISTING + [('@', 'TXT', self.record_content, '60')])]):
            self.client.add_txt_record(DOMAIN, DOMAIN, self.record_content, self.record_ttl)

        assert ('@', 'TXT', self.record_content) in self._sent_records(self.requests[2])

    def test_add_txt_record_subdomain(self):
        with self._mock_api([domain_list([DOMAIN]),
                             host_list(EXISTING), SET_HOSTS_OK, host_list(EXISTING)]):
            self.client.add_txt_record(DOMAIN, '_acme-challenge.foo.' + DOMAIN,
                                        self.record_content, self.record_ttl)

        assert ('_acme-challenge.foo', 'TXT', self.record_content) in self._sent_records(
            self.requests[2])

    def test_add_txt_record_fail_to_find_domain(self):
        with self._mock_api([domain_list(['other.invalid'])]):
            with pytest.raises(errors.PluginError, match='Unable to determine base domain'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

    def test_add_txt_record_error_finding_domain(self):
        with self._mock_api([API_ERROR]):
            with pytest.raises(errors.PluginError):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

    def test_add_txt_record_not_using_namecheap_dns(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING, is_our_dns='false')]):
            with pytest.raises(errors.PluginError, match='not using Namecheap DNS'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

    def test_add_txt_record_error_setting_hosts(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING), SET_HOSTS_FAILED]):
            with pytest.raises(errors.PluginError, match='did not confirm'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

    def test_add_txt_record_network_error(self):
        with self._mock_api([OSError('connection refused')]):
            with pytest.raises(errors.PluginError, match='Error communicating'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

    def test_add_txt_record_pages_domain_list(self):
        page_one = domain_list(['a.invalid'] * 1, total=2)
        page_two = domain_list([DOMAIN], total=2)
        with self._mock_api([page_one, page_two, host_list(EXISTING), SET_HOSTS_OK,
                             host_list(EXISTING)]):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                        self.record_ttl)

        assert self.requests[0]['Page'] == '1'
        assert self.requests[1]['Page'] == '2'

    def test_add_txt_record_warns_when_record_missing_afterwards(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING), SET_HOSTS_OK,
                             host_list(EXISTING)]):  # challenge record absent on read-back
            with mock.patch('certbot_dns_namecheap._internal.dns_namecheap.logger') as log:
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

        warnings = ' '.join(str(call) for call in log.warning.call_args_list)
        assert 'missing' in warnings

    def test_del_txt_record(self):
        target = (self.record_prefix, 'TXT', self.record_content, '60')
        other = (self.record_prefix, 'TXT', 'a-different-value', '60')
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING + [target, other]),
                             SET_HOSTS_OK, host_list(EXISTING + [other])]):
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        sent = self._sent_records(self.requests[2])
        # The matching record goes...
        assert (self.record_prefix, 'TXT', self.record_content) not in sent
        # ...while a same-name record with different content, and the rest of the
        # zone, stay.
        assert (self.record_prefix, 'TXT', 'a-different-value') in sent
        for name, type_, address, _ in EXISTING:
            assert (name, type_, address) in sent

    def test_del_txt_record_absent_is_a_no_op(self):
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING)]):
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        assert 'namecheap.domains.dns.setHosts' not in [r['Command'] for r in self.requests]

    def test_del_txt_record_error_finding_domain_is_not_raised(self):
        with self._mock_api([API_ERROR]):
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_setting_hosts_is_not_raised(self):
        target = (self.record_prefix, 'TXT', self.record_content, '60')
        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING + [target]),
                             SET_HOSTS_FAILED]):
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_can_empty_the_zone(self):
        """Removing the only record is legitimate, unlike an accidental wipe."""
        target = (self.record_prefix, 'TXT', self.record_content, '60')
        with self._mock_api([domain_list([DOMAIN]), host_list([target]), SET_HOSTS_OK,
                             host_list([])]):
            self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        assert self._sent_records(self.requests[2]) == set()

    def test_lock_serialises_zone_updates(self):
        """A second client cannot enter the read-modify-write while one holds it."""
        from certbot_dns_namecheap._internal.dns_namecheap import _NamecheapClient

        other = _NamecheapClient(API_USER, API_KEY, API_USER, CLIENT_IP,
                                 backup_dir=os.path.join(self.tempdir, 'bk'),
                                 lock_dir=os.path.join(self.tempdir, 'lk'))
        sld, tld = DOMAIN.partition('.')[0], DOMAIN.partition('.')[2]

        import fcntl
        with self.client._zone_lock(sld, tld):
            path = os.path.join(other.lock_dir, '%s.%s.lock' % (sld, tld))
            fd = os.open(path, os.O_WRONLY)
            try:
                with pytest.raises(OSError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

        # Released on exit, so it can be taken again.
        with other._zone_lock(sld, tld):
            pass

    def test_backup_failure_prevents_the_write(self):
        # A file where the backup directory should be: makedirs will fail.
        os.makedirs(self.tempdir, exist_ok=True)
        blocker = os.path.join(self.tempdir, 'blocker')
        with open(blocker, 'w'):
            pass
        self.client.backup_dir = os.path.join(blocker, 'bk')

        with self._mock_api([domain_list([DOMAIN]), host_list(EXISTING)]):
            with pytest.raises(errors.PluginError, match='Refusing to rewrite'):
                self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                            self.record_ttl)

        assert 'namecheap.domains.dns.setHosts' not in [r['Command'] for r in self.requests]


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
