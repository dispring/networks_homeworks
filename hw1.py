from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

BASE = "http://hw1.alexbers.com/"
USER_ID = "5fa226f7511d898aa8d48ad3ffd31eb9"

KINDS = {"cookie": "cookies", "заголовки": "headers", "параметры": "params",
         "данные формы": "data", "содержимым": "files"}


def parse_step(page):
    soup = BeautifulSoup(page, "html.parser")
    text = soup.get_text()
    if "Шаг #" not in text:
        return None

    link = soup.find("a")
    path = link["href"] if link else soup.find("code").text
    method = "GET" if link or "GET-запрос" in text else "POST"

    step = {"method": method, "url": urljoin(BASE, path),
            "cookies": {}, "headers": {}, "params": {}, "data": {}, "files": {}}
    for table in soup.find_all("table"):
        label = table.find_previous(string=lambda s: s.strip()).lower()
        for word, kind in KINDS.items():
            if word in label:
                for tr in table.find_all("tr")[1:]:
                    key, value = (td.text for td in tr.find_all("td"))
                    step[kind][key] = value
    return step


def do_step(step):
    files = {name: (name, content.encode("utf-8")) for name, content in step["files"].items()}
    return requests.request(
        step["method"], step["url"],
        cookies={"user": USER_ID, **step["cookies"]},
        headers=step["headers"],
        params=step["params"],
        data=step["data"],
        files=files,
        timeout=10,
    )


def main():
    r = requests.get(BASE, cookies={"user": USER_ID}, timeout=10)
    n = 0
    while step := parse_step(r.text):
        n += 1
        print(n, step["method"], step["url"])
        r = do_step(step)
        if r.status_code != 200:
            print(f"Статус {r.status_code}:\n{r.text}")
            return
    lines = (line.strip() for line in BeautifulSoup(r.text, "html.parser").get_text().splitlines())
    print("\n" + "\n".join(line for line in lines if line))


if __name__ == "__main__":
    main()