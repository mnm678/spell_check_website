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
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
  rv = client.post("/register", data=sent,
                    follow_redirects=True)
  assert b'Status: success' in rv.data

  #no duplicate registration
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
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
  sent = {"uname":"Bad", "pword":"test", "tfa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Incorrect' in rv.data

  #bad password
  sent = {"uname":"Test", "pword":"bad", "tfa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Incorrect' in rv.data

  #bad 2fa
  sent = {"uname":"Test", "pword":"test", "tfa":"dcba"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Two-factor failure' in rv.data

  #good login
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

def test_spell_check(client):
  #not logged in
  rv = client.get("/spell_check")
  assert b'Unauthorized' in rv.data
  assert b'inputtext' not in rv.data

  #log in the user
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
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

def test_history(client):
  #not logged in
  rv = client.get("/history")
  assert b'Unauthorized' in rv.data
  assert b'numqueries' not in rv.data

  #log in the user
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #now load the page
  rv = client.get("/history")
  assert b'numqueries' in rv.data
  assert b'There are 1 queries' in rv.data
  assert b'Words are mspelled' in rv.data

def test_query_review(client):
  #not logged in
  rv = client.get("/history/query1")
  assert b'Unauthorized' in rv.data
  assert b'Record View' not in rv.data

  #log in the user
  sent = {"uname":"Test", "pword":"test", "tfa":"abcd"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #load the page
  rv = client.get("/history/query1")
  assert b'Record View' in rv.data
  assert b'Test' in rv.data
  assert b'Words are mspelled' in rv.data

def test_second_user(client):
  #register Gollum/precious/1
  sent = {"uname":"Gollum", "pword":"precious", "tfa":"1"}
  rv = client.post("/register", data=sent,
                    follow_redirects=True)
  assert b'Status: success' in rv.data

  #log in user2
  sent = {"uname":"Gollum", "pword":"precious", "tfa":"1"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #spell check
  sent = {"inputtext":"My precioussss"}
  rv = client.post("/spell_check", data=sent, follow_redirects=True)
  assert b'id="textout">My precioussss' in rv.data
  assert b'id="misspelled"'in rv.data

  sent = {"inputtext":"Tricksy little hobbits"}
  rv = client.post("/spell_check", data=sent, follow_redirects=True)
  assert b'id="textout">Tricksy little hobbits' in rv.data
  assert b'id="misspelled"'in rv.data

  #history
  rv = client.get("/history")
  assert b'numqueries' in rv.data
  assert b'There are 2 queries' in rv.data
  assert b'My precioussss' in rv.data
  assert b'Tricksy little hobbits' in rv.data

  #can't see user1 query
  rv = client.get("/history/query1")
  assert b'Unauthorized' in rv.data
  assert b'Words are mspelled' not in rv.data

  #can see user2 query
  rv = client.get("/history/query2")
  assert b'My precioussss' in rv.data

def test_history_admin(client):
  #log in admin
  sent = {"uname":"admin", "pword":"Administrator@1", "tfa":"12345678901"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #admin history
  rv = client.get("/history")
  assert b'userquery' in rv.data

  #look at user2 history
  sent = {"userquery":"Gollum"}
  rv = client.post("/history", data=sent, follow_redirects=True)
  assert b'precioussss' in rv.data
  assert b'hobbits' in rv.data

  #can see user2 query
  rv = client.get("/history/query3")
  assert b'Tricksy little hobbits' in rv.data

def test_login_history(client):
  #not logged in
  rv = client.get("/login_history")
  assert b'Unauthorized' in rv.data
  assert b'userid' not in rv.data

  #log in admin
  sent = {"uname":"admin", "pword":"Administrator@1", "tfa":"12345678901"}
  rv = client.post("/login", data=sent,
                    follow_redirects=True)
  assert b'Result: success' in rv.data

  #logged in
  rv = client.get("/login_history")
  assert b'userid' in rv.data

  #get history for Test
  sent = {"userid":"Test"}
  rv = client.post("/login_history", data=sent, follow_redirects=True)
  assert b'login4_time' in rv.data

