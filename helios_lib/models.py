# -*- coding: utf-8 -*-
"""
Data Objects for Helios.

Ben Adida
(ben@adida.net)
"""
from __future__ import absolute_import
from collections import Counter
from datetime import datetime

from .crypto import electionalgs, algs, utils
from helios_lib import utils as heliosutils
from helios_lib.crypto.algs import EGPublicKey, EGSecretKey


class HeliosElection:
    def __init__(self):
        self.uid = None
        self.hash = None
        self.voters = list()
        self.frozen_at = None
        self.trustees = list()
        self.voting_starts_at = None
        self.voting_ends_at = None
        self.voters_hash = None
        self.num_cast_votes = None

    ELECTION_TYPES = (
        ('election', 'Election'),
        ('referendum', 'Referendum')
    )

    VOTING_METHOD_SIMPLE = 'simple'
    VOTING_METHOD_WEIGHTED = 'weighted'
    VOTING_METHOD_CUMULATIVE = 'cumulative'

    VOTING_METHOD_CHOICES = ((VOTING_METHOD_SIMPLE, 'Simple'),
                             (VOTING_METHOD_WEIGHTED, 'Weighted'),
                             (VOTING_METHOD_CUMULATIVE, 'Cumulative'))

    election_type = 'election'
    public_key = None
    private_key = None

    questions = None

    # encrypted tally, each a JSON string
    # used only for homomorphic tallies
    encrypted_tally = None

    # results of the election
    result = None

    # decryption proof, a JSON object
    # no longer needed since it's all trustees
    result_proof = list()

    voting_method = VOTING_METHOD_SIMPLE
    cumulative_weight = []

    @staticmethod
    def create_question(answers_count, minimum, maximum, result_type='relative'):
        return {
            'answers': answers_count,
            'min': minimum,
            'max': maximum,
            'result_type': result_type,  # absolute
            'tally_type': 'homomorphic',
            'choice_type': 'approval',

        }

    @property
    def is_weighted(self):
        return self.voting_method in [HeliosElection.VOTING_METHOD_WEIGHTED, HeliosElection.VOTING_METHOD_CUMULATIVE]

    @property
    def pretty_type(self):
        return dict(self.ELECTION_TYPES)[self.election_type]

    @property
    def encrypted_tally_hash(self):
        if not self.encrypted_tally:
            return None

        return utils.hash_b64(self.encrypted_tally.toJSON())

    def compute_tally(self, voters):
        """
        tally the election, assuming votes already verified
        """
        tally = self.init_tally()
        for voter in voters:
            tally.add_vote(voter.vote, verify_p=False, cumulative_weight=voter.cumulative_weight or voter.weight)

        self.encrypted_tally = tally

    def ready_for_decryption(self):
        return self.encrypted_tally != None

    def ready_for_decryption_combination(self):
        """
        do we have a tally from all trustees?
        """
        for t in HeliosTrustee.get_by_election(self):
            if not t.decryption_factors:
                return False

        return True

    def combine_decryptions(self):
        """
        combine all of the decryption results
        """

        # gather the decryption factors
        trustees = self.trustees
        decryption_factors = [t.decryption_factors for t in trustees]

        self.result = self.encrypted_tally.decrypt_from_factors(decryption_factors, self.public_key)

    def freeze(self):
        """
        election is frozen when the voter registration, questions, and trustees are finalized
        """
        # if len(self.issues_before_freeze) > 0:
        #     raise Exception("cannot freeze an election that has issues")

        # public key for trustees
        trustees = self.trustees
        combined_pk = trustees[0].public_key
        for t in trustees[1:]:
            combined_pk = combined_pk * t.public_key

        self.public_key = combined_pk

    def generate_helios_trustee(self, params):
        """
        generate a trustee including the secret key,
        thus a helios-based trustee
        """
        # FIXME: generate the keypair
        keypair = params.generate_keypair()

        # create the trustee
        trustee = HeliosTrustee()
        trustee.election = self
        trustee.public_key = keypair.pk
        trustee.secret_key = keypair.sk
        trustee.secret = heliosutils.random_string(12)
        trustee.public_key_hash = utils.hash_b64(utils.to_json(EGPublicKey(y=trustee.public_key.p,
                                                                           p=trustee.public_key.p,
                                                                           q=trustee.public_key.p,
                                                                           g=trustee.public_key.p).toJSONDict()))

        trustee.pok = trustee.secret_key.prove_sk(algs.DLog_challenge_generator)
        return trustee

    def get_helios_trustee(self):
        trustees_with_sk = [t for t in self.trustees if t.secret_key]
        if len(trustees_with_sk) > 0:
            return trustees_with_sk[0]
        else:
            return None

    def has_helios_trustee(self):
        return self.get_helios_trustee() is not None

    def helios_trustee_decrypt(self, trustee):
        tally = self.encrypted_tally
        tally.init_election(self)

        factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)

        trustee.decryption_factors = factors
        trustee.decryption_proofs = proof
        return trustee

    def init_tally(self):
        # FIXME: create the right kind of tally
        from helios_lib.workflows import homomorphic
        return homomorphic.Tally(election=self)

    @staticmethod
    def custom_winner(sorted_list, the_max):
        winner_list = []
        substitude_list = []
        equal_flag = False
        sorted_list = sorted_list[:]

        if the_max > 1:
            # count the occurances of each vote,if it's less than / equal the_max,we're good to go.
            # else return []
            #        while the_max >= 0:
            while the_max > 0:

                if sorted_list:
                    counter = Counter([y for (x, y) in sorted_list])
                    first_element, occurance = max(zip(counter.keys(), counter.values()))
                    if occurance <= the_max:
                        item = sorted_list.pop(0)
                        winner_list.append(item)

                        the_max -= 1
                    else:
                        equal_flag = True if occurance > 1 else False
                        break

                else:
                    break

            # making substitude list
            if equal_flag:
                for i in sorted_list:
                    if i[1] == sorted_list[0][1]:
                        substitude_list.append(i[0])

            final_result = [x[0] for x in winner_list]
            return [final_result, substitude_list]

        elif the_max == 1:
            if sorted_list:
                counter = Counter([y for (x, y) in sorted_list])
                first_element, occurance = max(zip(counter.keys(), counter.values()))
                if occurance > the_max:
                    equal_flag = True
                if equal_flag:
                    for i in sorted_list:
                        if i[1] == sorted_list[0][1]:
                            substitude_list.append(i[0])

                return [winner_list, substitude_list] if occurance > 1 else [[sorted_list[0][0]], substitude_list]
            else:
                return [[], []]

    @classmethod
    def one_question_winner(cls, question, result, num_cast_votes):
        """
        determining the winner for one question
        """
        # sort the answers , keep track of the index
        counts = sorted(enumerate(result), key=lambda x: x[1])
        counts.reverse()

        the_max = question['max'] or 1
        the_min = question['min'] or 0

        if question['result_type'] == 'relative':
            return HeliosElection.custom_winner(counts, the_max)

        elif question['result_type'] == 'absolute':
            qualified_list = []
            for candidate in counts:
                if candidate[1] >= (num_cast_votes / 2 + 1):
                    qualified_list.append(candidate)
            return HeliosElection.custom_winner(qualified_list, the_max)



            # if there's a max > 1, we assume that the top MAX win
            # return [c[0] for c in counts[:the_max]]


            # if max = 1, then depends on absolute or relative
            # if question['result_type'] == 'absolute':
            #   if counts[0][1] >= (num_cast_votes / 2 + 1):
            #     return [counts[0][0]]
            #   else:
            #     return []
            # else:
            # assumes that anything non-absolute is relative
            #      return [counts[0][0]]

    @property
    def winners(self):
        """
        Depending on the type of each question, determine the winners
        returns an array of winners for each question, aka an array of arrays.
        assumes that if there is a max to the question, that's how many winners there are.
        """
        winner_list = []
        equal_list = []
        if not self.questions:
            return
        for i in range(len(self.questions)):
            res = self.one_question_winner(self.questions[i], self.result[i], self.num_cast_votes)
            # [[],[]]
            winners, equals = res
            winner_list.append(winners)
            equal_list.append(equals)

        return [winner_list, equal_list]

    @property
    def pretty_result(self):
        if not self.result:
            return None

        # get the winners
        winners = self.winners

        raw_result = self.result
        prettified_result = []

        # loop through questions
        for i in range(len(self.questions)):
            q = self.questions[i]
            pretty_question = []

            # go through answers
            for j in range(len(q['answers'])):
                a = q['answers'][j]
                count = raw_result[i][j]
                pretty_question.append({'answer': a, 'count': count, 'winner': (j in winners[i])})

            prettified_result.append({'question': q['short_name'], 'answers': pretty_question})

        return prettified_result

    def encrypt_ballot(self, answers):
        """
        First, Check some issues, before one Voter want to encrypt answers of the one Election on the server side
        Next, Encrypt the answers
        @todo: Add more limitation to use this function.
        Args:
            answers:
              It's raw answers as string like "[[1], [2, 4], []]"
        Returns:
            Encrypted answers or Exception
        Raise:
          JsonLoadParserError
          ElectionIsNotFrozen
        """

        # if not self.frozen_at:
        #     raise ElectionIsNotFrozen()

        answers = utils.from_json(answers)

        from helios_lib.workflows import homomorphic

        ev = homomorphic.EncryptedVote.fromElectionAndAnswers(self, answers)
        return ev

    def __unicode__(self):
        return u'{}'.format(self.name)


class HeliosVoter:
    def __init__(self):
        self.vote_hash = None

    uid = None
    vote = None
    weight = int(1)
    cumulative_weight = list()

    @property
    def voter_id_hash(self):
        return utils.hash_b64(self.uid)

    @property
    def voter_type(self):
        return self.user.user_type

    def store_vote(self, cast_vote):
        # only store the vote if it's cast later than the current one
        if self.cast_at and cast_vote.cast_at < self.cast_at:
            return

        self.vote = cast_vote.vote
        self.vote_hash = cast_vote.vote_hash
        self.cast_at = cast_vote.cast_at
        self.cumulative_weight = cast_vote.cumulative_weight
        self.save()


class HeliosAuditedBallot:
    """
    ballots for auditing
    """
    election = None
    raw_vote = None
    vote_hash = None
    added_at = None

    def __init__(self, election, raw_vote, vote_hash, added_at):
        self.election = election
        self.raw_vote = raw_vote
        self.vote_hash = vote_hash
        self.added_at = added_at

    @staticmethod
    def store_audited_ballot(raw_vote, election):
        encrypted_vote = electionalgs.EncryptedVote.fromJSONDict(utils.from_json(raw_vote))
        vote_hash = encrypted_vote.get_hash()
        added_at = datetime.utcnow()
        return HeliosAuditedBallot(raw_vote=raw_vote, vote_hash=vote_hash, election=election, added_at=added_at)


class HeliosTrustee:
    election = None
    secret = None
    # public key
    public_key = None
    public_key_hash = None
    # secret key
    # if the secret key is present, this means
    # Helios is playing the role of the trustee.
    secret_key = None
    # proof of knowledge of secret key
    pok = None
    # decryption factors and proofs
    decryption_factors = None
    decryption_proofs = None

    def verify_decryption_proofs(self):
        """
        verify that the decryption proofs match the tally for the election
        """
        # verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
        return self.election.encrypted_tally.verify_decryption_proofs(self.decryption_factors, self.decryption_proofs,
                                                                      self.public_key,
                                                                      algs.EG_fiatshamir_challenge_generator)

    def set_public_key_from_json(self, public_key_json):
        """
        get the public key and the hash, and add it
        Args:
            public_key_json: String, json dump

        Returns:
        """
        public_key_and_proof = utils.from_json(public_key_json)
        self.public_key = algs.EGPublicKey.fromJSONDict(public_key_and_proof['public_key'])
        self.pok = algs.DLogProof.fromJSONDict(public_key_and_proof['pok'])
        # verify the pok
        if not self.public_key.verify_sk_proof(self.pok, algs.DLog_challenge_generator):
            raise Exception("bad pok for this public key")

        self.public_key_hash = utils.hash_b64(utils.to_json(self.public_key.toJSONDict()))

    @staticmethod
    def generate_helios_trustee_from_params(trustee_public_key, x, secret, helios_election):
        """
        Args:
            trustee_public_key:
            x:
            secret:
            helios_election:
        Returns:

        """
        public_key = EGPublicKey(**trustee_public_key)
        secret_key = EGSecretKey(pk=public_key, x=x)

        # create the trustee
        helios_trustee = HeliosTrustee()
        helios_trustee.election = helios_election
        helios_trustee.public_key = public_key
        helios_trustee.secret_key = secret_key
        helios_trustee.secret = secret

        return helios_trustee
