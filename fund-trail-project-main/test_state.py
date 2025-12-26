from app import app, get_state
from models import Transaction
with app.app_context():
    # Get all ACK numbers
    ack_nos = Transaction.query.with_entities(Transaction.ack_no).distinct().all()
    ack_list = [ack[0] for ack in ack_nos if ack[0]]
    print('Available ACK numbers:', ack_list)

    # Test with the first ACK number
    if ack_list:
        test_ack = ack_list[0]
        print(f'Testing with ACK: {test_ack}')

        t = Transaction.query.filter_by(ack_no=test_ack).first()
        if t:
            print('IFSC:', t.ifsc_code)
            print('Stored State:', t.state)
            dynamic_state = get_state(t.ifsc_code) if t.ifsc_code else 'No IFSC'
            print('Dynamic State:', dynamic_state)

        # Test the statewise_summary endpoint
        with app.test_client() as client:
            response = client.get(f'/statewise_summary/{test_ack}')
            print('Statewise summary response status:', response.status_code)
            if response.status_code == 200:
                data = response.get_json()
                print('Statewise summary data:', data)
            else:
              print('Error:', response.get_data(as_text=True))