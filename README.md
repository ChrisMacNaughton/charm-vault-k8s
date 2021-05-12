# vault

## Description

The vault charm deploys [Vault][vault-upstream], a tool for securely managing
secrets used in modern computing (e.g. passwords, certificates, API keys).


## Usage

TODO: Provide high-level usage, such as required config or relations

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