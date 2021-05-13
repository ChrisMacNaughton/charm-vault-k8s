# Copyright 2021 chris
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
                            '{ "backend": {"file": {"path": "/srv" } }, '
                            '"listener": {"tcp": {'
                                '"tls_disable": true, "address": "[::]:8200"} },'
                            '"default_lease_ttl": "168h", "max_lease_ttl": "720h", '
                            '"disable_mlock": true, '
                            '"cluster_addr": "http://[::]:8201",'
                            '"api_addr": "http://[::]:8200"}',
                        'VAULT_API_ADDR': 'http://[::]:8200',
                    },
                }
            },
        }
        self.assertEqual(self.harness.charm._vault_layer(), expected)

    def test_on_config_changed(self):
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

    @patch("hvac.Client")
    def test_on_install_initialized_unsealed(self, _client_mock):
        mock_client = Mock()
        mock_client.sys.is_initialized.return_value = True
        mock_client.sys.is_sealed.return_value = False
        _client_mock.return_value = mock_client
        self.harness.charm._on_install("mock_event")

    @patch("hvac.Client")
    def test_on_install_initialized(self, _client_mock):
        mock_client = Mock()
        mock_client.sys.is_initialized.return_value = False
        mock_client.sys.is_sealed.return_value = True
        mock_client.sys.initialize.return_value = {'root_token': 'test123', 'keys': [123]}
        _client_mock.return_value = mock_client
        self.harness.charm._on_install("mock_event")
        mock_client.sys.initialize.assert_called_once_with(secret_shares=1, secret_threshold=1)
        mock_client.sys.submit_unseal_key.assert_called_once_with(123)

    @patch("hvac.Client")
    def test_on_install_initialized_sealed(self, _client_mock):
        mock_client = Mock()
        mock_client.sys.is_initialized.return_value = True
        mock_client.sys.is_sealed.return_value = True
        _client_mock.return_value = mock_client
        self.harness.charm._stored.unseal_key = 1234
        self.harness.charm._on_install("mock_event")
        mock_client.sys.submit_unseal_key.assert_called_once_with(1234)
