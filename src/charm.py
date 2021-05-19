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
import os

from charms.icey_vault_k8s.v0.certificates import (
    CertificatesCharmEvents,
    CertificatesProvides,
)
import interface_vault_operator_peers


from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

logger = logging.getLogger(__name__)


STORAGE_PATH = "/var/lib/juju/storage/vault-storage/0"
CHARM_PKI_MP = "charm-pki-local"
CHARM_PKI_ROLE = "local"
CHARM_PKI_ROLE_CLIENT = "local-client"


class VaultCharm(CharmBase):
    """Charm the service."""

    client = None
    on = CertificatesCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        # Actions
        self.framework.observe(self.on.new_policy_action, self._new_policy_action)
        self.framework.observe(self.on.new_app_role_action, self._new_app_role_action)
        self.framework.observe(self.on.get_token_action, self._get_token_action)
        self.framework.observe(self.on.get_root_token_action, self._get_root_token_action)
        self.client = hvac.Client(url='http://localhost:8200')
        # Peers
        self.peers = interface_vault_operator_peers.VaultOperatorPeers(self, "peers")
        self.framework.observe(self.peers.on.has_peers, self._on_has_peers)

        if self.peers.root_token:
            self.client.token = self.peers.root_token

        # 'certificates' relation handling.
        self.certificates = CertificatesProvides(self)
        # When the 'certificates' is ready to configure, do so.
        # self.framework.observe(self.on.certificates_available, self._on_certificates_available)

    def _on_config_changed(self, event):
        """Handle the config-changed event"""
        # Get the vault container so we can configure/manipulate it
        container = self.unit.get_container("vault")
        # Create a new config layer
        layer = self._vault_layer()
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
        # Fix up storage permissions (broken on CDK on AWS otherwise)'
        os.chown(STORAGE_PATH, uid=100, gid=1000)

        # Initialize vault
        if self.unit.is_leader():
            if not self.client.sys.is_initialized():
                result = self.client.sys.initialize(secret_shares=1, secret_threshold=1)
                self.peers.set_root_token(result['root_token'])
                self.peers.set_unseal_key(result['keys'][0])
            self.client.token = self.peers.root_token
        # Unseal Vault
        if self.client.sys.is_sealed() && self.peers.unseal_key:
            self.client.sys.submit_unseal_key(self.peers.unseal_key)

        # Setup Vault CA
        self._generate_root_ca()
        # All is well, set an ActiveStatus
        self.unit.status = ActiveStatus()

    def _on_has_peers(self, _event):
        self._on_config_changed(event)

    def _generate_root_ca(self,
                          ttl='87599h', allow_any_name=True, allowed_domains=None,
                          allow_bare_domains=False, allow_subdomains=False,
                          allow_glob_domains=True, enforce_hostnames=False,
                          max_ttl='87598h'):
        """Configure Vault to generate a self-signed root CA.
        :param ttl: TTL of the root CA certificate
        :type ttl: string
        :param allow_any_name: Specifies if clients can request certs for any CN.
        :type allow_any_name: bool
        :param allow_any_name: List of CNs for which clients can request certs.
        :type allowed_domains: list
        :param allow_bare_domains: Specifies if clients can request certs for CNs
                                   exactly matching those in allowed_domains.
        :type allow_bare_domains: bool
        :param allow_subdomains: Specifies if clients can request certificates with
                                 CNs that are subdomains of those in
                                 allowed_domains, including wildcard subdomains.
        :type allow_subdomains: bool
        :param allow_glob_domains: Specifies whether CNs in allowed-domains can
                                   contain glob patterns (e.g.,
                                   'ftp*.example.com'), in which case clients will
                                   be able to request certificates for any CN
                                   matching the glob pattern.
        :type allow_glob_domains: bool
        :param enforce_hostnames: Specifies if only valid host names are allowed
                                  for CNs, DNS SANs, and the host part of email
                                  addresses.
        :type enforce_hostnames: bool
        :param max_ttl: Specifies the maximum Time To Live for generated certs.
        :type max_ttl: str
        """
        client = self.client
        self._configure_pki_backend(CHARM_PKI_MP)
        if self.is_ca_ready(CHARM_PKI_MP, CHARM_PKI_ROLE):
            return
        config = {
            'common_name': ("Vault Root Certificate Authority "
                            "({})".format(CHARM_PKI_MP)),
            'ttl': ttl,
        }
        csr_info = client.write(
            '{}/root/generate/internal'.format(CHARM_PKI_MP),
            **config)
        if not csr_info['data']:
            raise Exception(csr_info.get('warnings', 'unknown error'))
        cert = csr_info['data']['certificate']
        # Generated certificates can have the CRL location and the location of the
        # issuing certificate encoded.
        # addr = vault.get_access_address()
        # client.write(
        #     '{}/config/urls'.format(CHARM_PKI_MP),
        #     issuing_certificates="{}/v1/{}/ca".format(addr, CHARM_PKI_MP),
        #     crl_distribution_points="{}/v1/{}/crl".format(addr, CHARM_PKI_MP)
        # )

        self._write_roles(
            allow_any_name=allow_any_name,
            allowed_domains=allowed_domains,
            allow_bare_domains=allow_bare_domains,
            allow_subdomains=allow_subdomains,
            allow_glob_domains=allow_glob_domains,
            enforce_hostnames=enforce_hostnames,
            max_ttl=max_ttl,
            client_flag=True)
        return cert

    def sign_csr(self, csr, ttl='87599h'):
        return self.client.write(
            '{}/root/sign-intermediate'.format(CHARM_PKI_MP),
            csr=csr, format='pem_bundle', ttl=ttl)['data']['certificate']

    def _write_roles(self, **kwargs):
        # Configure a role for using this PKI to issue server certs
        self.client.write(
            '{}/roles/{}'.format(CHARM_PKI_MP, CHARM_PKI_ROLE),
            server_flag=True,
            **kwargs)
        # Configure a role for using this PKI to issue client-only certs
        self.client.write(
            '{}/roles/{}'.format(CHARM_PKI_MP, CHARM_PKI_ROLE_CLIENT),
            server_flag=False,  # client certs cannot be used as server certs
            **kwargs)

    def _configure_pki_backend(self, name, ttl=None, max_ttl=None):
        """Ensure a pki backend is enabled
        :param client: Vault client
        :type client: hvac.Client
        :param name: Name of backend to enable
        :type name: str
        :param ttl: TTL
        :type ttl: str
        """
        if not self._is_backend_mounted(name):
            self.client.enable_secret_backend(
                backend_type='pki',
                description='Charm created PKI backend',
                mount_point=name,
                # Default ttl to 10 years
                config={
                    'default_lease_ttl': ttl or '8759h',
                    'max_lease_ttl': max_ttl or '87600h'})

    def _is_backend_mounted(self, name):
        """Check if the supplied backend is mounted
        :returns: Whether mount point is in use
        :rtype: bool
        """
        return '{}/'.format(name) in self.client.list_secret_backends()

    def is_ca_ready(self, name=CHARM_PKI_MP, role=CHARM_PKI_ROLE):
        """Check if CA is ready for use
        :returns: Whether CA is ready
        :rtype: bool
        """
        return self.client.read('{}/roles/{}'.format(name, role)) is not None

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
        event.set_results({"token": self.peers.root_token})


if __name__ == "__main__":
    # use_juju_for_storage is used to workaround
    main(VaultCharm)
