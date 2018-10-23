class AppException(Exception):
    """
    Base class for App framework exceptions.
    Subclasses should provide  `.message` properties.
    """
    message = 'A application error occurred.'

    def __init__(self, message=None):
        if message is not None:
            self.message = message
        else:
            self.message = self.message

    def __str__(self):
        return self.message


# Util
class JsonLoadParserError(AppException):
    message = 'Invalid json data.'


class DictObjectRequired(AppException):
    message = 'Invalid dict data'


class IntegerValueNeeds(AppException):
    message = 'An Integer value needs.'


# Election

class InvalidElectionID(AppException):
    message = 'Invalid Election ID'


class ElectionIsNotStarted(AppException):
    message = 'This Election is not started'


class ElectionIsNotStopped(AppException):
    message = 'This Election is not stopped'


class ElectionIsTallied(AppException):
    message = 'This election has already been tallied, you can no longer cast a vote.'


class ElectionIsStopped(AppException):
    message = 'This election has stopped.'


class ElectionIsNotFrozen(AppException):
    message = 'Election is not frozen.'


class ElectionIsNotReleased(AppException):
    message = 'Election is not released yet'


class DetectCastVoteWithDuplicateVoteHash(AppException):
    message = 'You send same vote encrypted data twice, so we ignore this one.'


class NoVotesCast(AppException):
    message = 'No votes have been cast in this election. At least one vote must be cast before you compute the tally.'


class FieldRequired(AppException):
    message = 'This field is required'


class TrusteeInvalidFactorsAndProofs(AppException):
    message = 'Invalid factors and proofs'


class InvalidVoteForDecryption(AppException):
    message = "You don't have permission to decrypt this vote"


class InvalidParametersForThisAction(AppException):
    message = 'Trustee/Voter does not belong to this election'


class ReVoteIsDenied(AppException):
    message = "Re vote is denied"
