import pytest
from app import app

@pytest.fixture
def client():
  app.config['TESTING'] = True
  app.config['WTF_CSRF_ENABLED'] = False
  with app.test_client() as client:
    yield client

def test_registration(client):
  #Does the page load
  rv = client.get("/register")
  assert b'uname' in rv.data
  assert b'pword' in rv.data
  assert b'2fa' in rv.data
  assert b'Status: success' not in rv.data

  #register Test/test/abcd
  sent = {"uname":"Test", "pword":"test", "2fa":"abcd"}
  rv = client.post("/register", data=sent,
                    follow_redirects=True)
  assert b'Status: success' in rv.data

  #no duplicate registration
  sent = {"uname":"Test", "pword":"test", "2fa":"abcd"}
  rv = client.post("/register", data=sent,
                    follow_redirects=True)
  assert b'Status: failure' in rv.data


def test_login(client):
  #register Test/test/abcd
  #sent = {"uname":"Test", "pword":"test", "2fa":"abcd"}
  #rv = client.post("/register", data=sent,
                    #follow_redirects=True)
  #a3ssert b'Status: success' in rv.data

  #does the page load
  rv = client.get("/login")
  assert b'uname' in rv.data
  assert b'pword' in rv.data
  assert b'2fa' in rv.data

  #bad username
  sent = {"uname":"Bad", "pword":"test", "2fa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Incorrect' in rv.data

  #bad password
  sent = {"uname":"Test", "pword":"bad", "2fa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Incorrect' in rv.data

  #bad 2fa
  sent = {"uname":"Test", "pword":"test", "2fa":"dcba"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Two-factor failure' in rv.data

  #good login
  sent = {"uname":"Test", "pword":"test", "2fa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

def test_spell_check(client):
  #not logged in
  rv = client.get("/spell_check")
  assert b'Not logged in' in rv.data
  assert b'inputtext' not in rv.data

  #log in the user
  sent = {"uname":"Test", "pword":"test", "2fa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #now load the page
  rv = client.get("/spell_check")
  assert b'inputtext' in rv.data

  sent = {"inputtext":"Words are mspelled"}
  rv = client.post("/spell_check", data=sent, follow_redirects=True)
  assert b'id="textout">Words are mspelled' in rv.data
  assert b'id="misspelled"'in rv.data
