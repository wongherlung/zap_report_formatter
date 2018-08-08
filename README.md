# zap_report_formatter

OWASP Zed Attack Proxy (ZAP) produces reports that are formatted in either `json` or `xml`. However, the format of the `xml` reports generated are not friendly to integrate with Jenkin's Junit plugin. This is normally what we would want to do if we want to perform ZAP scans as part of our CI/CD workflow.

## Usage

```python
import zap_report_formatter from zap_report_formatter

zap_report_formatter.format('path to ZAP json report', 'path to json whitelist file', 'output path of xml file')
```

Here is what the `json` whitelist file should be like:

```json
{
  "42": {
    "name": "Source Code Disclosure - SVN",
    "regex_uris": [
      "http://example.localhost"
    ],
    "reason": "Reason."
  }
}
```
