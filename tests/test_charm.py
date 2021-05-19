# Copyright 2021 Chris MacNaughton <chris.macnaughton@canonical.com>, Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import Mock, patch

from charm import VaultCharm
from ops.model import ActiveStatus
from ops.testing import Harness


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.harness.charm.client = Mock()
        self.harness.charm.client.list_secret_backends.return_value = 'secret'
        self.harness.charm.peers = Mock()
        self.maxDiff = 4000

    def test_vault_layer(self):
        # Test with empty config.
        expected = {
            "summary": "vault layer",
            "description": "pebble config layer for vault",
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        'VAULT_LOCAL_CONFIG':
                            '{"backend": {"file": {"path": "/srv"}}, '
                            '"listener": {"tcp": {'
                                '"tls_disable": true, "address": "[::]:8200"}}, '
                            '"default_lease_ttl": "168h", "max_lease_ttl": "720h", '
                            '"disable_mlock": true, '
                            '"cluster_addr": "http://127.0.1.1:8201", '
                            '"api_addr": "http://127.0.1.1:8200"}',
                        'VAULT_API_ADDR': 'http://[::]:8200',
                    },
                }
            },
        }
        VaultCharm._bind_address = '127.0.1.1'
        self.assertEqual(self.harness.charm._vault_layer(), expected)

    @patch('os.chown')
    @patch('charm.VaultCharm._bind_address')
    def test_on_config_changed(self, _mock_bind_address, _chown):
        plan = self.harness.get_container_pebble_plan("vault")
        self.assertEqual(plan.to_dict(), {})
        self.harness.update_config()
        # Get the expected layer from the vault method (tested above)
        expected = self.harness.charm._vault_layer()
        expected.pop("summary", "")
        expected.pop("description", "")
        # Check the plan is as expected
        plan = self.harness.get_container_pebble_plan("vault")
        self.assertEqual(plan.to_dict(), expected)
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
        container = self.harness.model.unit.get_container("vault")
        self.assertEqual(container.get_service("vault").is_running(), True)

    @patch('os.chown')
    @patch('charm.VaultCharm._bind_address')
    def test_on_config_changed_initialized_unsealed(self, _mock_bind_address, _chown):
        self.harness.charm.client.sys.is_initialized.return_value = True
        self.harness.charm.client.sys.is_sealed.return_value = False
        self.harness.charm._on_config_changed("mock_event")

    @patch('charm.VaultCharm.unit')
    @patch('os.chown')
    @patch('charm.VaultCharm._bind_address')
    def test_on_config_changed_uninitialized(self, _mock_bind_address, _chown, _unit):
        self.harness.charm.client.sys.is_initialized.return_value = False
        self.harness.charm.client.sys.is_sealed.return_value = True
        self.harness.charm.client.sys.initialize.return_value = {
            'root_token': 'test123', 'keys': [123]}
        _unit.is_leader.return_value = True
        self.harness.charm.peers.unseal_key = 123
        self.harness.charm._on_config_changed("mock_event")
        self.harness.charm.client.sys.initialize.assert_called_once_with(
            secret_shares=1, secret_threshold=1)
        self.harness.charm.peers.set_root_token.assert_called_once_with('test123')
        self.harness.charm.peers.set_unseal_key.assert_called_once_with(123)
        self.harness.charm.client.sys.submit_unseal_key.assert_called_once_with(123)

    @patch('os.chown')
    @patch('charm.VaultCharm._bind_address')
    def test_on_config_changed_initialized_sealed(self, _mock_bind_address, _chown):
        self.harness.charm.client.sys.is_initialized.return_value = True
        self.harness.charm.client.sys.is_sealed.return_value = True
        self.harness.charm.peers.unseal_key = 1234
        self.harness.charm._on_config_changed("mock_event")
        self.harness.charm.client.sys.submit_unseal_key.assert_called_once_with(1234)

    def test_new_policy_action(self):
        mock_event = Mock(params={
            "name": "test",
            "hcl": "{backend}", "backend": "secret",
        })
        self.harness.charm._new_policy_action(mock_event)
        self.harness.charm.client.set_policy.assert_called_once_with("test", "secret")

    def test_new_app_role_action(self):
        mock_event = Mock(params={
            'name': 'test-name',
            'policy': 'policy-name',
            'cidr': '10.1.2.3/32',
        })
        self.harness.charm._new_app_role_action(mock_event)
        self.harness.charm.client.create_role.assert_called_once_with(
            'test-name',
            token_ttl='60s',
            token_max_ttl='60s',
            policies=['policy-name'],
            bind_secret_id='true',
            bound_cidr_list='10.1.2.3/32')

    def test_get_token_action(self):
        mock_event = Mock(params={
            'name': 'test-name',
            'cidr': '10.1.2.3/32',
        })
        self.harness.charm.client.write.return_value = {'wrap_info': {'token': 'token1234'}}
        self.harness.charm._get_token_action(mock_event)
        self.harness.charm.client.write.assert_called_once_with(
            'auth/approle/role/test-name/secret-id',
            wrap_ttl='1h', cidr_list='10.1.2.3/32'
        )
        mock_event.called_once_with({"token": "token1234"})

    def test_get_root_token_action(self):
        mock_event = Mock()
        self.harness.charm.peers.root_token = "root-token-123"
        self.harness.charm._get_root_token_action(mock_event)
        mock_event.called_once_with({"token": "root-token-123"})
