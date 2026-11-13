from classes.HttpHeaders import HttpHeaders


def test_req_separates_host_and_path():
    assert HttpHeaders(host='example.com', path='/wp-login.php').req == 'example.com/wp-login.php'
    assert HttpHeaders(host='example.com', path='wp-login.php').req == 'example.com/wp-login.php'
    assert HttpHeaders(host='example.com', path='').req == 'example.com'
    assert HttpHeaders(host='', path='/.env').req == '/.env'
