---------
TokenRing
---------

TokenRing is a back-end for the Python `keyring
<https://keyring.readthedocs.io>`_ module, which uses a `hard token
<https://en.wikipedia.org/wiki/Hard_token>`_ to encrypt your collection of
passwords as a large `Fernet token
<https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet>`_,
composed of individual password entries, each of which is separately encrypted
as a smaller Fernet token of its own.

---------------------------
Background and Threat Model
---------------------------

The keyring module is a great starting point for managing confidential
materials in your Python applications.  Anything that needs to connect to a
network-backed service for an account requires some kind of saved password or
API token for nearly every operation.  By using the keyring API, you give the
user control over how that information is accessed, via configuration and
plugins.

However, using its default backend on every platform, Keyring provides silent
access to your credentials.  Only macOS even provides a mechanism that *could*
require user interaction to access a credential; Windows provides literally
nothing and desktop Linux provides only the ability to temporarily lock *all*
secrets behind your login password.

For a lot of applications, this is fine; “arbitrary code execution on your
computer” is a pretty high bar for an attacker to achieve, and there's a lot of
nasty stuff they can get up to if they get it; it would be annoying to have to
log in once every 30 seconds so that background tasks could check your email or
on every single ``git fetch``.

But some operations are dangerous and infrequent enough that your computer
should *really* not be able to do them without you noticing.  Just for a couple
of examples: uploading widely-used packages to PyPI that can execute code on
millions of computers, or issuing bank transfers to your payment provider.

This is where ``tokenring`` comes in.

------------
Requirements
------------

You need to have an NFC authenticator with the `hmac-secret
<https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension>`_
extension.  In practice, in my limited experience, this means a YubiCo
authenticator of some recent vintage.

-----
Usage
-----

Step 0: make sure the software that you're using uses ``keyring`` to fetch its secrets
--------------------------------------------------------------------------------------

Many things which handle sensitive information do, but you might need to submit
a patch first.

Step 1: install ``tokenring`` into the environment where you're accessing extra-sensitive secrets
---------------------------------------------------------------------------------------------------------

You probably don't want ``tokenring`` globally installed; or indeed installed
in most of your Python environments, since it is a high-priority backend that
will take over for all Keyring API calls by default, and therefore require your
hard-token to access every time.

For example, let's say you upload all your packages with twine.  First, install
twine itself with `pipx <https://pypa.github.io/pipx/>`_ so it gets its own
dedicated virtual environment.  Then, ``pipx inject twine --include-apps
tokenring``; since this always injects ``keyring`` as well, ``twine`` will
always use ``tokenring`` as a backend.

Step 2: run the agent
----------------------

This is currently mandatory on Windows due to `this issue
<https://github.com/glyph/tokenring/issues/1>`_ unless you are running your
application as an administrator.  On other platforms, it'll fall back to local
access within the requesting process, but you'll have to tap your authenticator
one extra time per process in that case, to unlock the vault.

``pipx install tokenring``, and run ``tokenring agent path/to/your/tokenring.vault``.


Step 3: call ``keyring.set_password`` and ``keyring.get_password`` in whatever application you'd like to use
-------------------------------------------------------------------------------------------------------------

If the ``keyring`` command on your shell's ``PATH`` is in an environment with
``tokenring`` installed, you can just use ``keyring set`` and ``keyring get``
to test this, but as a convenience, to make sure you're inspecting
``tokenring`` directly, you can use the ``tokenring set`` and ``tokenring get``
commands, which behave similarly but will never use any other keyring backend.

To use Twine with a secret stored in ``tokenring``, for example, the full
workflow would be:

1. open a terminal and run ``tokenring agent my.vault``
2. create a token at https://pypi.org/manage/account/token/
3. open a terminal and run ``tokenring set https://upload.pypi.org/legacy/
   __token__``, then paste your token when prompted
4. in whatever project you'd like to upload, ``TWINE_USERNAME=__token__ twine
   upload dist/*``
