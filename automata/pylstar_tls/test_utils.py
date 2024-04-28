from pylstar.Letter import Letter
from utils import fill_answer_with, Endpoint


def test_fill_answer_with():
    assert fill_answer_with([Letter("A")], "B", 3) == [
        Letter("A"),
        Letter("B"),
        Letter("B"),
    ]
    assert fill_answer_with([Letter("A"), Letter("B")], "C", 2) == [
        Letter("A"),
        Letter("B"),
    ]


def test_endpoint():
    endpoint = Endpoint("127.0.0.1:4433")
    host, port = endpoint.as_tuple()
    assert host == "127.0.0.1"
    assert port == 4433
    assert endpoint.check()

    endpoint = Endpoint("DOES_not_EXIST:123")
    assert not endpoint.check()
