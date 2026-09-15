const escapedUrl = "https\x3a\x2f\x2fapi\u002eencoded\u002ecom\x2fapi\x2fv1\x2fsecret_data";
fetch(escapedUrl, {
  headers: {
    "X-Custom-Auth": "Basic YWRtaW46U3VwZXJTZWNyZXQxMjM="
  }
});
