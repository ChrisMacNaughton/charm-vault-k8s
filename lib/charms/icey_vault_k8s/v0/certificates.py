"""Library for the certificates relation

This library contains the Requires and Provides classes for handling
the certificates interface.

Import `CertificateRequires` in your charm, with two required options:
    - "self" (the charm itself)
    - config_dict

"""
import json
import logging

from ops.charm import CharmEvents
from ops.framework import EventBase, EventSource, Object
from ops.model import BlockedStatus

# The unique Charmhub library identifier, never change it
LIBID = "1ae5557f795442119164fe6ce0e85eaf"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

REQUIRED_CERTIFICATES_RELATION_FIELDS = {
    "service-hostname",
}

OPTIONAL_CERTIFICATES_RELATION_FIELDS = {
    "service-certificate-signing-request",
}

logger = logging.getLogger(__name__)


class CertificatesAvailableEvent(EventBase):
    certificates_data = None
    def __init__(self, handle, certificates_data=None):
        super().__init__(handle)
        self.certificates_data = certificates_data

    def snapshot(self):
        return {
            "certificates_data": self.certificates_data,
        }

    def restore(self, snapshot):
        self.certificates_data = snapshot["certificates_data"]


class CertificatesCharmEvents(CharmEvents):
    """Custom charm events."""

    certificates_available = EventSource(CertificatesAvailableEvent)


class CertificatesRequires(Object):
    """This class defines the functionality for the 'requires' side of the 'certificates' relation.

    Hook events observed:
        - relation-changed
    """
    def __init__(self, charm, config_dict):
        super().__init__(charm, "certificates")

        self.framework.observe(charm.on["certificates"].relation_changed, self._on_relation_changed)

        self.config_dict = config_dict

    def _config_dict_errors(self, update_only=False):
        """Check our config dict for errors."""
        blocked_message = "Error in certificates relation, check `juju debug-log`"
        unknown = [
            x
            for x in self.config_dict
            if x not in REQUIRED_CERTIFICATES_RELATION_FIELDS | OPTIONAL_CERTIFICATES_RELATION_FIELDS
        ]
        if unknown:
            logger.error(
                "Certificate relation error, unknown key(s) in config dictionary found: %s",
                ", ".join(unknown),
            )
            self.model.unit.status = BlockedStatus(blocked_message)
            return True
        if not update_only:
            missing = [x for x in REQUIRED_CERTIFICATES_RELATION_FIELDS if x not in self.config_dict]
            if missing:
                logger.error(
                    "Certificate relation error, missing required key(s) in config dictionary: %s",
                    ", ".join(missing),
                )
                self.model.unit.status = BlockedStatus(blocked_message)
                return True
        return False

    def _on_relation_changed(self, event):
        """Handle the relation-changed event."""
        # `self.unit` isn't available here, so use `self.model.unit`.
        if self.model.unit.is_leader():
            if self._config_dict_errors():
                return
            for key in self.config_dict:
                event.relation.data[self.model.app][key] = str(self.config_dict[key])

    def update_config(self, config_dict):
        """Allow for updates to relation."""
        if self.model.unit.is_leader():
            self.config_dict = config_dict
            if self._config_dict_errors(update_only=True):
                return
            relation = self.model.get_relation("certificates")
            if relation:
                for key in self.config_dict:
                    relation.data[self.model.app][key] = str(self.config_dict[key])


class CertificatesProvides(Object):
    """This class defines the functionality for the 'provides' side of the 'certificates' relation.

    Hook events observed:
        - relation-changed
    """

    certificates_data = {}

    def __init__(self, charm):
        super().__init__(charm, "certificates")
        # Observe the relation-changed hook event and bind
        # self.on_relation_changed() to handle the event.
        self.framework.observe(charm.on["certificates"].relation_changed, self._on_relation_changed)
        self.charm = charm

    def _on_relation_changed(self, event):
        """Handle a change to the certificates relation.

        Confirm we have the fields we expect to receive."""
        # `self.unit` isn't available here, so use `self.model.unit`.
        if not self.model.unit.is_leader():
            return
        logger.info("relation data: %s", repr(event.relation.data[event.app]))
        certificates_data = {
            field: event.relation.data[event.app].get(field)
            for field in REQUIRED_CERTIFICATES_RELATION_FIELDS | OPTIONAL_CERTIFICATES_RELATION_FIELDS
        }
        logger.info("Certificates data: %s", json.dumps(certificates_data))
        missing_fields = sorted(
            [
                field
                for field in REQUIRED_CERTIFICATES_RELATION_FIELDS
                if certificates_data.get(field) is None
            ]
        )

        if missing_fields:
            logger.error(
                "Missing required data fields for certificates relation: {}".format(
                    ", ".join(missing_fields)
                )
            )
            self.model.unit.status = BlockedStatus(
                "Missing fields for certificates: {}".format(", ".join(missing_fields))
            )
        # Create an event that our charm can use to decide it's okay to
        # configure the certificates.
        # self.charm.on.certificates_available.emit(certificates_data=certificates_data)
        try:
            if self.charm.is_ca_ready():
                certificate = self.charm.sign_csr(certificates_data['service-certificate-signing-request'])
                event.relation.data[self.model.app]['certificate'] = str(certificate)
        except Exception:
            event.defer()
