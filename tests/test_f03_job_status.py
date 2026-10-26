from unittest.mock import MagicMock, patch

from worker import queue_triage_job


def test_f03_queue_uses_ticket_id_as_job_id():
    ticket_id = "ticket-456"

    payload = {
        "ticket_id": ticket_id,
        "raw_text": "Test support request",
    }

    mock_job = MagicMock()
    mock_job.id = ticket_id

    with patch("worker.task_queue") as mock_queue:
        mock_queue.enqueue.return_value = mock_job
        mock_queue.count = 1

        job = queue_triage_job(payload)

        assert job.id == ticket_id

        assert mock_queue.enqueue.call_args.kwargs["job_id"] == ticket_id
