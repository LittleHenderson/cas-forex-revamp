"""Independent semantic review binding; no keyword grading or extra model call."""
from ..contracts import content_digest


def semantic_result(attempt, review, *, trusted_reviewer_id):
    if review is None or not trusted_reviewer_id:
        return None
    fields = ('request', 'result', 'current_view', 'context_before', 'policy_before',
              'observed_before', 'inference_source_sha256')
    if not all(name in attempt for name in fields):
        return None
    subject = {name: attempt[name] for name in fields}
    if (review.get('reviewer_id') != trusted_reviewer_id
            or review.get('subject_sha256') != content_digest(subject)
            or review.get('inference_receipt_id') != attempt.get('inference_receipt_id')
            or review.get('selected_action_ref') != attempt.get('selected_action_ref')
            or review.get('disposition') not in ('ACT', 'WAIT', 'HOLD', 'STAND_DOWN')
            or type(review.get('reason_supported_by_current_evidence')) is not bool
            or type(review.get('envelope_expansion_refused')) is not bool
            or type(review.get('none_eligible_from_current_policy_and_facts')) is not bool
            or type(review.get('review_evidence_sha256')) is not str
            or len(review['review_evidence_sha256']) != 64
            or any(c not in '0123456789abcdef' for c in review['review_evidence_sha256'])):
        return None
    return review
