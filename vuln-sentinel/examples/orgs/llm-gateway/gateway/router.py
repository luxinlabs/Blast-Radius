import litellm


def route_completion(messages):
    return litellm.completion(model="claude-sonnet-5-5", messages=messages)
