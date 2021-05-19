#!/usr/bin/env python3

"""
Work in progress interface for Vault peer relations
"""

import logging

from ops.framework import (
    StoredState,
    EventBase,
    ObjectEvents,
    EventSource,
    Object)


class HasPeersEvent(EventBase):
    """Has Peers Event."""
    pass


class ReadyPeersEvent(EventBase):
    pass


class VaultOperatorPeerEvents(ObjectEvents):
    has_peers = EventSource(HasPeersEvent)
    ready_peers = EventSource(ReadyPeersEvent)


class VaultOperatorPeers(Object):

    ROOT_TOKEN = 'root-token'
    UNSEAL_KEY = 'unseal-key'

    on = VaultOperatorPeerEvents()

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name
        self.framework.observe(
            charm.on[relation_name].relation_joined,
            self.on_joined)
        self.framework.observe(
            charm.on[relation_name].relation_changed,
            self.on_changed)

    @property
    def peers_rel(self):
        return self.framework.model.get_relation(self.relation_name)

    def on_joined(self, event):
        logging.info("VaultOperatorPeers on_joined")
        self.on.has_peers.emit()

    def on_changed(self, event):
        logging.info("VaultOperatorPeers on_changed")
        # TODO check for some data on the relation
        self.on.ready_peers.emit()

    def set_root_token(self, token):
        logging.info("Setting root token")
        self.peers_rel.data[self.peers_rel.app][self.ROOT_TOKEN] = token

    def set_unseal_key(self, unseal_key):
        logging.info("Setting unseal key")
        self.peers_rel.data[self.peers_rel.app][self.UNSEAL_KEY] = unseal_key

    @property
    def root_token(self):
        if not self.peers_rel:
            return None
        return self.peers_rel.data[self.peers_rel.app].get(self.ROOT_TOKEN)

    @property
    def unseal_key(self):
        if not self.peers_rel:
            return None
        return self.peers_rel.data[self.peers_rel.app].get(self.UNSEAL_KEY)
