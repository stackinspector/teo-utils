def get_log_list(secret, date, zone_id):
    import hashlib
    import hmac
    import json
    import sys
    import time
    from datetime import datetime
    from http.client import HTTPSConnection

    (secret_id, secret_key) = secret

    limit = 300
    # adhoc for current situation
    offset = 0

    date_str = date.strftime("%Y-%m-%d")

    params = {
        "StartTime": date_str + "T00:00:00+08:00",
        "EndTime": date_str + "T23:59:00+08:00",
        "ZoneIds": [zone_id],
        "Domains": [],
        "Limit": limit,
        "Offset": offset,
    }

    service = "teo"
    host = "teo.tencentcloudapi.com"
    version = "2022-09-01"
    action = "DownloadL7Logs"
    payload = json.dumps(params)
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

    # 步骤 1：拼接规范请求串
    http_request_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    content_type = "application/json; charset=utf-8"
    canonical_headers = f"content-type:{content_type}\nhost:{host}\nx-tc-action:{action.lower()}\n"
    signed_headers = "content-type;host;x-tc-action"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = "\n".join([http_request_method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, hashed_request_payload])

    # 步骤 2：拼接待签名字符串
    credential_scope = f"{date}/{service}/tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = "\n".join([algorithm, str(timestamp), credential_scope, hashed_canonical_request])

    # 步骤 3：计算签名
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    secret_date = sign(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # 步骤 4：拼接 Authorization
    authorization = f"{algorithm} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    # 步骤 5：构造并发起请求
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": timestamp,
        "X-TC-Version": version,
    }

    req = HTTPSConnection(host)
    req.request("POST", "/", headers=headers, body=payload.encode("utf-8"))
    resp = json.loads(req.getresponse().read())

    # adhoc for current situation
    assert resp["Response"]["TotalCount"] < limit

    return resp["Response"]["Data"]

def make_logs(data):
    import json
    from urllib.request import urlopen
    from gzip import decompress
    import lzma

    logs = []
    for item in data:
        itemreq = urlopen(item["Url"])
        itemdata = decompress(itemreq.read()).decode("utf-8")
        item["DecompressedSize"] = len(itemdata)
        print(item)
        item.pop("Url")
        logs.append(json.dumps(item))
        logs.append("\n")
        logs.append(itemdata)
    log_bytes = bytes("".join(logs), encoding="utf8")
    log_xz = lzma.compress(log_bytes, preset=lzma.PRESET_EXTREME)
    return log_xz

def calc_date(date_str):
    from datetime import date, datetime, timedelta
    if date_str is None:
        return date.today() - timedelta(days=2)
    else:
        return datetime.strptime(date_str, "%Y-%m-%d")

def filename(date, zone_id):
    return "{}-{}.xz".format(date.strftime("%Y%m%d"), zone_id)

from pathlib import Path
secret = (Path("./sid").read_text(), Path("./sk").read_text())
zone_id = Path("./zid").read_text()
date = calc_date(None)
with open(filename(date, zone_id), "xb") as f:
    f.write(make_logs(get_log_list(secret, date, zone_id)))
