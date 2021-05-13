#!/usr/bin/env python3
# Copyright 2021 Chris MacNaughton <chris.macnaughton@canonical.com>, Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import hvac
import logging

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


STORAGE_PATH = "/var/lib/juju/storage/vault_storage/0"


class VaultCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()
    client = None

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        # Actions
        self.framework.observe(self.on.new_policy_action, self._new_policy_action)
        self.framework.observe(self.on.new_app_role_action, self._new_app_role_action)
        self.framework.observe(self.on.get_token_action, self._get_token_action)
        self.framework.observe(self.on.get_root_token_action, self._get_root_token_action)
        self._stored.set_default(root_token=None, unseal_key=None)
        self.client = hvac.Client(url='http://localhost:8200')
        if self._stored.root_token:
            self.client.token = self._stored.root_token

    def _on_config_changed(self, event):
        """Handle the config-changed event"""
        # Get the vault container so we can configure/manipulate it
        container = self.unit.get_container("vault")
        # Create a new config layer
        layer = self._vault_layer()
        # Get the current config
        plan = container.get_plan()
        # Check if there are any changes to services
        services = container.get_plan().to_dict().get("services", {})
        if services != layer["services"]:
            # Changes were made, add the new layer
            container.add_layer("vault", layer, combine=True)
            logging.info("Added updated layer 'vault' to Pebble plan")
            # Stop the service if it is already running
            if container.get_service("vault").is_running():
                container.stop("vault")
            # Restart it and report a new status to Juju
            container.start("vault")
            logging.info("Restarted vault service")

        if not self.client.sys.is_initialized():
            result = self.client.sys.initialize(secret_shares=1, secret_threshold=1)
            self._stored.root_token = result['root_token']
            self._stored.unseal_key = result['keys'][0]
        self.client.token = self._stored.root_token
        if self.client.sys.is_sealed():
            self.client.sys.submit_unseal_key(self._stored.unseal_key)

        # All is well, set an ActiveStatus
        self.unit.status = ActiveStatus()

    def _vault_layer(self):
        return {
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

    def _new_policy_action(self, event):
        self.client.set_policy(
            event.params['name'],
            event.params['hcl'].format(
                backend=event.params['backend']))

    def _new_app_role_action(self, event):
        approle_name = event.params['name']
        policy_name = event.params['policy']
        cidr = event.params['cidr']
        # new_role = (approle_name not in self.client.list_roles())
        self.client.create_role(
            approle_name,
            token_ttl='60s',
            token_max_ttl='60s',
            policies=[policy_name],
            bind_secret_id='true',
            bound_cidr_list=cidr
        )

    def _get_token_action(self, event):
        name = event.params['name']
        cidr = event.params['cidr']
        response = self.client.write('auth/approle/role/{}/secret-id'.format(name),
                                     wrap_ttl='1h', cidr_list=cidr)
        event.set_results({"token": response['wrap_info']['token']})

    def _get_root_token_action(self, event):
        event.set_results({"token": self._stored.root_token})

        # event.set_results({"token": token, "role_id": role_id})

    # def _on_fortune_action(self, event):
    #     """Just an example to show how to receive actions.

    #     TEMPLATE-TODO: change this example to suit your needs.
    #     If you don't need to handle actions, you can remove this method,
    #     the hook created in __init__.py for it, the corresponding test,
    #     and the actions.py file.

    #     Learn more about actions at https://juju.is/docs/sdk/actions
    #     """
    #     fail = event.params["fail"]
    #     if fail:
    #         event.fail(fail)
    #     else:
    #         event.set_results(
    #           {"fortune": "A bug in the code is worth two in the documentation."})


if __name__ == "__main__":
    main(VaultCharm, use_juju_for_storage=True)
