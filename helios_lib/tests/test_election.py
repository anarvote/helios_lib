from helios_lib.config import ELGAMAL_PARAMS
from helios_lib.crypto.algs import EGSecretKey, EGPublicKey
from helios_lib.models import HeliosElection, HeliosVoter, HeliosTrustee
from helios_lib.workflows.homomorphic import Tally

"""
$ pytest --fulltrace -s helios_lib/
v pytest --cov-report html:cov_html  -s --cov=helios_lib helios_lib
"""


class TestHeliosElection:
    election = None

    @staticmethod
    def create_election():
        return HeliosElection()

    @staticmethod
    def create_default_trustee(election):
        return election.generate_helios_trustee(ELGAMAL_PARAMS)

    @staticmethod
    def create_voters(count=4):
        return [HeliosVoter() for _ in range(count)]

    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 1
            v.cumulative_weight = []

        election.voters[0].vote = election.encrypt_ballot('[[0,4]]')
        election.voters[1].vote = election.encrypt_ballot('[[0]]')
        election.voters[2].vote = election.encrypt_ballot('[[1]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4]]')

        for v in election.voters:
            v.vote.verify(election)

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestHeliosElection.setup_voters(e)
        e.num_cast_votes = 4

        e.compute_tally(e.voters)
        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        pass

    def test_election_result(self):
        e = self.setup_election()
        assert e.result == [[2, 2, 0, 0, 2]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[]], [[4, 1, 0]]]
        assert 1 == 1


class TestHeliosElectionMultiTrustee(TestHeliosElection):
    # This sample public key generated on the client side with js
    public_key = "{\"pok\": {\"challenge\": \"597880577963290531114829618055806847628653671236\", \"commitment\": \"15203548448442609213344112968213030622808829377618892292146899519981165474308797289608821083975000388578757751035331052674591716485590040115812595973465734452152875717639244113646958123134517196061637273223053780481568146343259951119159172941178167770491546388614924012052078273289314955844627985438996675936104387815348363801233422823095821577575171246328331197235543849422799615799179803336093236170008379170709104276916359459867988879078078201190754802546826255129110171247883033957067001179215387411307478358091886116971655669980253870177868456574530684754492662197366984084748124851969949903663744543132882315490\", \"response\": \"20355104078884340424828736136385498487108267328047283396239301362508873049469\"}, \"public_key\": {\"g\": \"14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533\", \"p\": \"16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071\", \"q\": \"61329566248342901292543872769978950870633559608669337131139375508370458778917\", \"y\": \"13408277724923531643093604574867829700878573161518708230288211642226592491245162574991986497961257986010718814416934251382231223182163717138264486243562615444111296385118189317113458239547359025878429804490769328923819311269678002568996442063793736335141686385044421604422813351913797130145582149373323984067320915081917630196933430141455519931232767424481208523000534613471437091380691299825495754153353072369392031832662868344157876544193736573248795756857756196711573256442302836891492715274060377463840503164185354220697751816705385634324438545911008587888858700301058310954741487266025579494358147717088619804301\"}}"

    # This sample secret key generated for above specific public key on the client side with js
    secret_key = {"public_key": {
        "g": 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533,
        "p": 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071,
        "q": 61329566248342901292543872769978950870633559608669337131139375508370458778917,
        "y": 13408277724923531643093604574867829700878573161518708230288211642226592491245162574991986497961257986010718814416934251382231223182163717138264486243562615444111296385118189317113458239547359025878429804490769328923819311269678002568996442063793736335141686385044421604422813351913797130145582149373323984067320915081917630196933430141455519931232767424481208523000534613471437091380691299825495754153353072369392031832662868344157876544193736573248795756857756196711573256442302836891492715274060377463840503164185354220697751816705385634324438545911008587888858700301058310954741487266025579494358147717088619804301},
        "x": 24581090442784763262902541072609438516159389581898710268560275562065407852205}

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        trustee_extra_one = HeliosTrustee()
        trustee_extra_one.set_public_key_from_json(TestHeliosElectionMultiTrustee.public_key)
        e.trustees.append(trustee_default)
        e.trustees.append(trustee_extra_one)
        q = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestHeliosElection.setup_voters(e)
        e.num_cast_votes = 4
        #
        e.compute_tally(e.voters)
        tally = e.encrypted_tally
        #
        public_key = EGPublicKey(**TestHeliosElectionMultiTrustee.secret_key['public_key'])
        secret_key = EGSecretKey(pk=public_key, x=TestHeliosElectionMultiTrustee.secret_key['x'])
        trustee_extra_one.secret_key = secret_key

        # It's same as calling `e.helios_trustee_decrypt(e.get_helios_trustee())`
        trustee_default.decryption_factors, trustee_default.decryption_proofs = tally.decryption_factors_and_proofs(
            trustee_default.secret_key)

        trustee_extra_one.decryption_factors, trustee_extra_one.decryption_proofs = tally.decryption_factors_and_proofs(
            trustee_extra_one.secret_key)

        e.combine_decryptions()

        return e


class TestHeliosElectionMultiQuestion(TestHeliosElection):
    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 1
            v.cumulative_weight = []

        election.voters[0].vote = election.encrypt_ballot('[[0,4], [1,2]]')
        election.voters[1].vote = election.encrypt_ballot('[[0], [4,2]]')
        election.voters[2].vote = election.encrypt_ballot('[[1], [0]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4], [1,2]]')

        for v in election.voters:
            v.vote.verify(election)

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q1 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        q2 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')

        e.questions = [q1, q2]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestHeliosElectionMultiQuestion.setup_voters(e)
        e.num_cast_votes = 4

        e.compute_tally(e.voters)
        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    def test_election_result(self):
        e = self.setup_election()
        assert e.result == [[2, 2, 0, 0, 2], [1, 2, 3, 0, 1]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[], [2, 1]], [[4, 1, 0], []]]


class TestHeliosElectionMultiQuestionMultiTrustee(TestHeliosElectionMultiTrustee):
    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 1
            v.cumulative_weight = []

        election.voters[0].vote = election.encrypt_ballot('[[0,4], [1,3]]')
        election.voters[1].vote = election.encrypt_ballot('[[0], [4,2]]')
        election.voters[2].vote = election.encrypt_ballot('[[1], [0]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4], [1,2]]')

        for v in election.voters:
            v.vote.verify(election)

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        trustee_extra_one = HeliosTrustee()
        trustee_extra_one.set_public_key_from_json(TestHeliosElectionMultiTrustee.public_key)
        e.trustees.append(trustee_default)
        e.trustees.append(trustee_extra_one)
        q1 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        q2 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q1, q2]

        e.voters = TestHeliosElectionMultiQuestionMultiTrustee.create_voters()
        e.freeze()
        TestHeliosElectionMultiQuestionMultiTrustee.setup_voters(e)
        e.num_cast_votes = 4
        #
        e.compute_tally(e.voters)
        tally = e.encrypted_tally
        #
        public_key = EGPublicKey(**TestHeliosElectionMultiTrustee.secret_key['public_key'])
        secret_key = EGSecretKey(pk=public_key, x=TestHeliosElectionMultiTrustee.secret_key['x'])
        trustee_extra_one.secret_key = secret_key

        # It's same as calling `e.helios_trustee_decrypt(e.get_helios_trustee())`
        trustee_default.decryption_factors, trustee_default.decryption_proofs = tally.decryption_factors_and_proofs(
            trustee_default.secret_key)

        trustee_extra_one.decryption_factors, trustee_extra_one.decryption_proofs = tally.decryption_factors_and_proofs(
            trustee_extra_one.secret_key)

        e.combine_decryptions()

        return e

    def test_election_result(self):
        e = self.setup_election()
        assert e.result == [[2, 2, 0, 0, 2], [1, 2, 2, 1, 1]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[], [2, 1]], [[4, 1, 0], []]]


class TestDecryptOneVote(TestHeliosElection):
    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestHeliosElection.setup_voters(e)
        e.num_cast_votes = 4

        e.compute_tally(e.voters)
        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    def test_decrypt_one_vote_one_trustee(self):
        election = self.setup_election()
        voter = election.voters[0]
        tally = election.init_tally()
        tally.add_vote(voter.vote, verify_p=False, cumulative_weight=voter.cumulative_weight or voter.weight)
        # election.encrypted_tally = tally
        # tally = self.encrypted_tally
        # tally.init_election(election)

        # trustee = election.get_helios_trustee()
        trustees = election.trustees
        for trustee in trustees:
            factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)
            trustee.decryption_factors = factors
            trustee.decryption_proofs = proof

        decryption_factors = [t.decryption_factors for t in trustees]
        result = tally.decrypt_from_factors(decryption_factors, election.public_key)
        assert result == [[1, 0, 0, 0, 1]]
        return result

    def test_decrypt_one_vote_multiple_trustees(self):
        election = TestHeliosElectionMultiTrustee.setup_election()
        voter = election.voters[0]
        tally = election.init_tally()
        tally.add_vote(voter.vote, verify_p=False, cumulative_weight=voter.cumulative_weight or voter.weight)

        # trustee = election.get_helios_trustee()
        trustees = election.trustees
        for trustee in trustees:
            factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)
            trustee.decryption_factors = factors
            trustee.decryption_proofs = proof

        decryption_factors = [t.decryption_factors for t in trustees]
        result = tally.decrypt_from_factors(decryption_factors, election.public_key)
        assert result == [[1, 0, 0, 0, 1]]
        return result


class TestWeightedElection(TestHeliosElection):
    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestWeightedElection.setup_voters(e)
        e.num_cast_votes = 4

        e.compute_tally(e.voters)
        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 20
            v.cumulative_weight = []

        election.voters[0].vote = election.encrypt_ballot('[[0,4]]')
        election.voters[1].vote = election.encrypt_ballot('[[0]]')
        election.voters[2].vote = election.encrypt_ballot('[[1]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4]]')

        for v in election.voters:
            v.vote.verify(election)

    def test_election_result(self):
        e = self.setup_election()

        assert e.result == [[40, 40, 0, 0, 40]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[]], [[4, 1, 0]]]


class TestCumulativeElection(TestHeliosElection):
    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        e.questions = [q]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestCumulativeElection.setup_voters(e)
        e.num_cast_votes = 4

        e.compute_tally(e.voters)
        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            # v.weight = 1
            v.cumulative_weight = [[50, 100, 0, 0, 0]]
        # if answer is selected in encrypt_ballot and the corresponding value in
        # cumulative weight is zero (cumulative_weight[4]) it returns one instead of zero
        election.voters[0].vote = election.encrypt_ballot('[[0,4]]')
        election.voters[1].vote = election.encrypt_ballot('[[0]]')
        election.voters[2].vote = election.encrypt_ballot('[[1]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4]]')

        for v in election.voters:
            v.vote.verify(election)

    def test_election_result(self):
        e = self.setup_election()
        assert e.result == [[100, 200, 0, 0, 2]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[1, 0]], [[]]]


class TestElectionResults(TestHeliosElection):
    @staticmethod
    def create_voters(count=4):
        return [HeliosVoter() for _ in range(count)]

    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 1
            v.cumulative_weight = []

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q1 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=1, result_type='relative')
        q2 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=3, result_type='relative')
        q3 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=1, result_type='absolute')
        q4 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=3, result_type='absolute')

        e.questions = [q1, q2, q3, q4]

        e.voters = TestElectionResults.create_voters()
        e.freeze()
        TestElectionResults.setup_voters(e)
        e.num_cast_votes = 4

        return e

    def test_custom_winner_rel_max_1(self):
        result = [5, 4, 3, 1, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[0], result, num_cast_votes)
        assert winner == [[0], []]

    def test_election_result(self):
        pass

    def test_election_winner(self):
        pass

    def test_custom_winner_rel_max_1_with_equal(self):
        result = [5, 5, 3, 1, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[0], result, num_cast_votes)
        assert winner == [[], [1, 0]]

    def test_custom_winner_rel_max_gt1(self):
        result = [5, 4, 2, 3, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[1], result, num_cast_votes)
        assert winner == [[0, 1, 3], []]

    def test_custom_winner_rel_max_gt1_with_equals(self):
        result = [5, 4, 4, 4, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[1], result, num_cast_votes)
        assert winner == [[0], [3, 2, 1]]

    def test_custom_winner_abs_max_1_no_qualified(self):
        result = [2, 1, 1, 1, 2]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[2], result, num_cast_votes)
        assert winner == [[], []]

    def test_custom_winner_abs_max_gt1_no_qualified(self):
        result = [2, 1, 1, 1, 2]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[3], result, num_cast_votes)
        assert winner, [[], []]

    def test_custom_winner_abs_max_1(self):
        result = [5, 4, 3, 1, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[2], result, num_cast_votes)
        assert winner == [[0], []]

    def test_custom_winner_abs_max_1_with_equals(self):
        result = [4, 4, 4, 1, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[2], result, num_cast_votes)
        assert winner, [[], [2, 1, 0]]

    def test_custom_winner_abs_max_gt1(self):
        result = [5, 5, 4, 3, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[3], result, num_cast_votes)
        assert winner == [[1, 0, 2], []]

    def test_custom_winner_abs_max_gt1_with_equals(self):
        result = [4, 4, 3, 3, 1]
        num_cast_votes = 5
        election = self.setup_election()
        winner = election.one_question_winner(election.questions[3], result, num_cast_votes)
        assert winner, [[1, 0], [3, 2]]


class TestHeliosElectionAggregateTally(TestHeliosElection):
    @staticmethod
    def setup_voters(election):
        for v in election.voters:
            v.weight = 1
            v.cumulative_weight = []

        election.voters[0].vote = election.encrypt_ballot('[[0,4], [1,2]]')
        election.voters[1].vote = election.encrypt_ballot('[[0], [4,2]]')
        election.voters[2].vote = election.encrypt_ballot('[[1], [0]]')
        election.voters[3].vote = election.encrypt_ballot('[[1,4], [1,2]]')

        for v in election.voters:
            v.vote.verify(election)

    @staticmethod
    def setup_election():
        e = TestHeliosElection.create_election()
        trustee_default = TestHeliosElection.create_default_trustee(e)
        e.trustees.append(trustee_default)
        q1 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')
        q2 = HeliosElection.create_question(answers_count=5, minimum=0, maximum=2, result_type='relative')

        e.questions = [q1, q2]

        e.voters = TestHeliosElection.create_voters()
        e.freeze()
        TestHeliosElectionMultiQuestion.setup_voters(e)
        e.num_cast_votes = 4

        num_tallied = 0
        e.compute_tally(e.voters[:2])
        encrypted_tally_01 = e.encrypted_tally.tally
        e.compute_tally(e.voters[2:])
        num_tallied += e.encrypted_tally.num_tallied
        encrypted_tally_02 = e.encrypted_tally.tally
        tallies = [encrypted_tally_01, encrypted_tally_02]
        num_tallied += e.encrypted_tally.num_tallied

        e.encrypted_tally = Tally.aggregate_tallies(e, tallies)
        e.encrypted_tally.num_tallied = num_tallied

        helios_trustee = e.get_helios_trustee()
        e.helios_trustee_decrypt(helios_trustee)
        e.combine_decryptions()

        return e

    def test_election_result(self):
        e = self.setup_election()
        assert e.result == [[2, 2, 0, 0, 2], [1, 2, 3, 0, 1]]

    def test_election_winner(self):
        e = self.setup_election()
        assert e.winners == [[[], [2, 1]], [[4, 1, 0], []]]
