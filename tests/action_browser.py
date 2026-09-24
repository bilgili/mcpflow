"""Small browser-form driver: follow actual GET routes and posted aliases."""

import re
from html import unescape


def control(card, name):
    for label in re.finditer(r'<label for="([^"]+)">(.*?)</label>', card, re.DOTALL):
        text = unescape(re.sub("<[^>]*>", "", label[2])).strip()
        if text.removesuffix("required").strip() == name:
            return re.search(
                r'<(?:input|select|textarea)\b[^>]*id="'
                + re.escape(label[1])
                + r'"[^>]*>',
                card,
            )[0]
    raise AssertionError(f"No control labelled {name!r}")


def action_post(client, url, **kwargs):
    """Submit ordinary behavior tests via a real rendered browser form."""
    if "/actions/" not in url or "?" in url:
        return client.post(url, **kwargs)
    page_url, name = url.rsplit("/", 1)
    from test_child_actions import cards

    card = cards(client.get(page_url).text).get(name)
    if card is None:
        return client.post(url, **kwargs)
    target = unescape(re.search(r'<form[^>]*action="([^"]+)"', card)[1])
    data = {}
    for raw, value in kwargs.pop("data", {}).items():
        tag = control(card, raw)
        alias = re.search(r'name="([^"]+)"', tag)[1]
        if tag.startswith("<select"):
            select = re.search(re.escape(tag) + r"(.*?)</select>", card, re.DOTALL)[1]
            options = {
                unescape(label): alias
                for alias, label in re.findall(
                    r'<option value="([^"]*)"[^>]*>(.*?)</option>', select
                )
            }
            value = options.get(value, value)
        data[alias] = value
    return client.post(target, data=data, **kwargs)
