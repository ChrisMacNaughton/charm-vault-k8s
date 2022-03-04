"""Library for the certificates relation

This is an interface designed to be compatible with the
existing Vault charm's relations

This library contains the Requires and Provides classes for handling
the certificates interface.

Import `CertificateRequires` in your charm, with two required options:
    - "self" (the charm itself)
    - config_dict
"""
from collections import defaultdict
import json
import logging

from ops.charm import CharmEvents
from ops.framework import EventBase, EventSource, Object
from ops.model import ActiveStatus, BlockedStatus

# The unique Charmhub library identifier, never change it
LIBID = "1ae5557f795442119164fe6ce0e85eaf"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2

CERTIFICATES_RELATION_FIELDS = {
    "common_name", "cert_type", "cert_requests",
    "client_cert_requests", "application_cert_requests",
    "certificate_name", "sans", "unit_name", 
}

logger = logging.getLogger(__name__)


class InsecureCertificatesProvides(Object):
    """This class defines the functionality for the 'provides' side of the 'certificates' relation.

    Hook events observed:
        - relation-changed
    """

    def __init__(self, charm):
        super().__init__(charm, "insecure-certificates")
        # Observe the relation-changed hook event and bind
        # self.on_relation_changed() to handle the event.
        self.framework.observe(
            charm.on["insecure-certificates"].relation_changed, self._on_relation_changed)
        self.charm = charm

    def _on_relation_changed(self, event):
        """Handle a change to the certificates relation.

        Confirm we have the fields we expect to receive."""
        try:
            certificates_data = {
                field: event.relation.data[event.unit].get(field)
                for field in
                CERTIFICATES_RELATION_FIELDS
            }
        except KeyError:
            logger.info("Apparently the relation has gone away!")
            return
        logger.info("Raw certificates data: {}".format(event.relation.data[event.unit]))
        # Create an event that our charm can use to decide it's okay to
        # configure the certificates.
        try:
            if self.charm.is_ca_ready():
                ca = self.charm.get_ca()
                unit_name = certificates_data['unit_name']
                
                if certificates_data['common_name']:
                    certificate = self.charm.issue_certificate(
                        certificates_data, 'server')
                    if ca is None:
                        logging.info("Trying to set CA in common_name request")
                        ca = certificate['issuing_ca']
                    cert_key = '{}.{}'.format(unit_name.replace('/', '_'), 'server')
                    logging.info(f"Setting {certificates_data['common_name']} certificate_data for {self.model.unit}")
                    event.relation.data[self.model.unit]['{}.key'.format(cert_key)] = str(certificate['private_key'])
                    event.relation.data[self.model.unit]['{}.cert'.format(cert_key)] = str(certificate['certificate'])
                reqs = json.loads(certificates_data.get('cert_requests') or '{}')
                certificates = defaultdict(lambda: {})
                for common_name, req in reqs.items():
                    logging.info("Processing cert_requests: {}".format(req))
                    certificate = self.charm.issue_certificate(
                        certificates_data, 'server')
                    if ca is None:
                        logging.info("Trying to set CA in cert_requests")
                        ca = certificate['issuing_ca']
                    certificates[common_name]['key'] = str(certificate['private_key'])
                    certificates[common_name]['cert'] = str(certificate['certificate'])

                reqs = json.loads(certificates_data.get('client_cert_requests') or '{}')
                for common_name, req in reqs.items():
                    logging.info("Processing client_cert_requests: {}".format(req))
                    certificate = self.charm.issue_certificate(
                        certificates_data, 'client')
                    if ca is None:
                        logging.info("Trying to set CA in client_cert_requests")
                        ca = certificate['issuing_ca']
                    certificates[common_name]['key'] = str(certificate['private_key'])
                    certificates[common_name]['cert'] = str(certificate['certificate'])

                # reqs = json.loads(certificates_data.get('application_cert_requests') or '{}')
                # for common_name, req in reqs.items():
                #     logging.info("Processing application_cert_requests: {}".format(req))
                #     processed_applications = []
                #     if req['application_name'] in processed_applications:
                #         logger.info('Already done {}'.format(req['application_name']))
                #         continue
                #     else:
                #         processed_applications.append(req['application_name'])
                #     certificate = self.charm.issue_certificate(
                #         certificates_data, 'server')
                #     if ca is None:
                #         ca = certificate['issuing_ca']
                #     relations[common_name]['key'] = str(certificate['private_key'])
                #     relations[common_name]['cert'] = str(certificate['certificate'])
                for common_name, certs in certificates.items():
                    logging.info(f"Setting {common_name} certificate_data for {self.model.unit}")
                    event.relation.data[self.model.unit][common_name] = json.dumps(certs)
                logging.info(f"Setting CA to {ca} for {self.model.unit}")
                event.relation.data[self.model.unit]['ca'] = str(ca)
                event.relation.data[self.model.unit]['chain'] = str(ca)
            else:
                logger.info("CA isn't ready")
                event.defer()
        except Exception as e:
            logger.warning(f"Error in setting up certificate: {e}")
            import traceback
            # import sys
            logging.warning(traceback.format_exc())
            event.defer()
