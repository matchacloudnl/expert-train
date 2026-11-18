"""Well-known software shown under the "Software" tab of CVE Watcher.

To watch another product, add an entry here and (optionally) a label in cve/app.js.
  search:  keyword(s) sent to the NVD keyword search
  pattern: regex the CVE description must match (keeps unrelated mentions out)
  kev:     regex tested on "vendor product" of CISA KEV entries
  min:     minimum CVSS score to show
"""
import re

SOFTWARE = {
    "php": dict(search=["php"], min=7.0,
                pattern=r"\bphp\b[^.]{0,40}(version|before|\d)|\bphp-(fpm|cgi)\b",
                kev=r"\bphp\b"),
    "nginx": dict(search=["nginx"], min=7.0,
                  pattern=r"\bnginx\b",
                  kev=r"\bnginx\b"),
    "java": dict(search=["java"], min=7.0,
                 pattern=r"oracle java|java se|java platform|java runtime|\bopenjdk\b|\bjdk\b|\bjre\b",
                 kev=r"\bjava\b|\bjdk\b|\bopenjdk\b"),
    "apache": dict(search=["apache http server"], min=7.0,
                   pattern=r"apache http server|\bhttpd\b",
                   kev=r"http server|\bhttpd\b"),
    "openssl": dict(search=["openssl"], min=7.0,
                    pattern=r"\bopenssl\b[^.]{0,40}(version|before|\d)",
                    kev=r"\bopenssl\b"),
    "openssh": dict(search=["openssh"], min=7.0,
                    pattern=r"\bopenssh\b",
                    kev=r"\bopenssh\b"),
    "mysql": dict(search=["mysql", "mariadb"], min=7.0,
                  pattern=r"\bmysql (server|before|\d)|\bmariadb (server|before|\d)",
                  kev=r"\bmysql\b|\bmariadb\b"),
    "postgresql": dict(search=["postgresql"], min=7.0,
                       pattern=r"\bpostgresql\b[^.]{0,40}(version|before|\d|server)",
                       kev=r"\bpostgresql\b"),
    "docker": dict(search=["docker engine", "docker desktop"], min=7.0,
                   pattern=r"docker (engine|desktop)|\bmoby\b",
                   kev=r"\bdocker\b|\bmoby\b"),
    "chrome": dict(search=["google chrome"], min=8.0,
                   pattern=r"google chrome|chromium",
                   kev=r"\bchrome\b|\bchromium\b"),
    "firefox": dict(search=["firefox"], min=8.0,
                    pattern=r"\bfirefox\b",
                    kev=r"\bfirefox\b"),
}

# CVEs about add-ons for these products are not about the product itself
EXCLUDE = re.compile(
    r"wordpress|plugin|theme|joomla|drupal|laravel|prestashop|magento|module for|extension for|browser extension",
    re.I)
