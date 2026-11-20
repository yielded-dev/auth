# Third-party notices

`@yielded/auth` uses Effect as its runtime and includes the attributed
form-encoding adaptation below for provider-specific HTTP Basic token requests.
No upstream OAuth SDK is a runtime dependency.

## oauth4webapi 3.8.8

Version: **3.8.8**. Commit: **`916b97952dbf431d8b72f369840de54f5a286e4d`**.

Runtime adaptation: [src/index.ts, `formUrlEncode`](https://github.com/panva/oauth4webapi/blob/916b97952dbf431d8b72f369840de54f5a286e4d/src/index.ts#L1867),
used by upstream `ClientSecretBasic`, is adapted as
[src/oauth/providers/shared/http.ts, `basicComponent`](src/oauth/providers/shared/http.ts).
It form-encodes each credential component before joining them with a colon,
including escaped punctuation and `+` for spaces. The MIT license below covers
this adaptation.

```text
The MIT License (MIT)

Copyright (c) 2022 Filip Skokan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
