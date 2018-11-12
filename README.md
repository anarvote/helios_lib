The Helios Lib
===============


[![Build Status](https://travis-ci.org/anarvote/helios_lib.svg?branch=master)](https://travis-ci.org/anarvote/helios_lib)



This is [Helios-Server](https://github.com/benadida/helios-server) (Helios is an end-to-end verifiable voting system.) as library,

This helios_lib version is completely independent of Django.


Install
-------

    >>> pip install helios_lib


Test
----

    >>> pytest --fulltrace -s helios_lib/


Example
-------

```python
from helios_lib.models import HeliosElection, HeliosVoter
from helios_lib.config import ELGAMAL_PARAMS

# Create election
helios_election = HeliosElection()

# Add trustee
trustee_default = helios_election.generate_helios_trustee(ELGAMAL_PARAMS)
helios_election.trustees.append(trustee_default)

# Add questions
question = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
helios_election.questions = [question]

# Add voters
voters_count = 4
helios_election.voters = [HeliosVoter() for _ in range(voters_count)]

# Freeze the election
helios_election.freeze()

# Cast votes, Encrypt votes of voters on the helios_lib side
helios_election.voters[0].vote = helios_election.encrypt_ballot('[[0,4]]')
helios_election.voters[1].vote = helios_election.encrypt_ballot('[[0]]')
helios_election.voters[2].vote = helios_election.encrypt_ballot('[[1]]')
helios_election.voters[3].vote = helios_election.encrypt_ballot('[[1,4]]')

# Verify votes of voters
for v in helios_election.voters:
    v.vote.verify(helios_election)

# Tally election
helios_election.num_cast_votes = 4
helios_election.compute_tally(helios_election.voters)
helios_trustee = helios_election.get_helios_trustee()
helios_election.helios_trustee_decrypt(helios_trustee)
helios_election.combine_decryptions()

# Result of election
assert helios_election.result == [[2, 2, 0, 0, 2]]

```



For more complex example refer to tests


Using Redis backend
----

In the root of project:

    pip install -r requirements.txt

set proper environment variables:

    $DLOG_BACKEND='redis'
    $REDIS_HOST='localhost'
    $REDIS_PORT='6379'
    $REDIS_TABLE_LENGHT='10000'


Fire up a python shell and type:

    >>> from helios_lib.redis_dlog_backend import RedisDlog
    >>> RedisDlog(1000).compute()

To create 1000 entries. (default value is 10000)

Now you can count up to 1000 votes for each answer.
This may take a lot of memory for big entries.