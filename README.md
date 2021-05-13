# vault

## Description

The vault charm deploys [Vault][vault-upstream], a tool for securely managing
secrets used in modern computing (e.g. passwords, certificates, API keys).


## Usage

After deploying the Vault charm, there are actions available to access both
the root token created at initialization as well as generating a new token
with an AppRole.

An example to get started with Vault:

    juju run-action --wait vault/leader get-root-token
    export VAULT_ADDR=http://$IP_OF_VAULT_CONTAINER:8200
    export VAULT_TOKEN=$TOKEN_FROM_ACTION
    $ vault secrets list
    > Path          Type         Accessor              Description
    > ----          ----         --------              -----------
    > cubbyhole/    cubbyhole    cubbyhole_67e758ac    per-token private secret storage
    > identity/     identity     identity_fab0254e     identity store
    > sys/          system       system_04fe0ff2       system endpoints used for control, policy and debugging

## Build

To build:

    git clone https://github.com/chrismacnaughton/charm-vault.git
    cd charm-vault/
    charmcraft build

## Usage

Run it like so:

    juju deploy ./vault.charm --resource vault-image=vault

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests`:

    ./run_tests

<!-- LINKS -->

[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/