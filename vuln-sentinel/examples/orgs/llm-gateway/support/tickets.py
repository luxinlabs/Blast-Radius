import requests


def fetch_ticket(ticket_id):
    return requests.get(f"https://helpdesk.example.invalid/tickets/{ticket_id}").json()
