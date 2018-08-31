def parse_querystring(qs):
    kvs = qs.split("&")
    parsed = {}
    for kv in kvs:
        k, v = kv.split("=")
        parsed[k] = v
    return parsed


def profile_for(email):
    # sanitize email
    clean_email = email.strip("&")
    cleaner_email = clean_email.strip("=")

    return {
        "email": cleaner_email,
        "uid": 10,
        "role": "user"
    }


def create_querystring(json):
    return "&".join(str(k) + "=" + str(v) for k, v in json.items())


def main():
    testing_qs = "foo=bar&baz=qux&zap=zazzle"
    testing_output = {
        "foo": "bar",
        "baz": "qux",
        "zap": "zazzle"
    }
    assert parse_querystring(testing_qs) == testing_output

    target_querystring = "email=foo@bar.com&uid=10&role=user"
    profile_json = profile_for("foo@bar.com")
    profile_querystring = create_querystring(profile_json)
    assert profile_querystring == target_querystring


if __name__ == "__main__":
    main()
