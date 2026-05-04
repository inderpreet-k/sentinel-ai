\# Sentinel AI — SDK Integration Guide



\## Your API URL (after deployment)

Replace `https://sentinel-ai-3xkl.onrender.com` with your real deployed URL.



\---



\## PHP



```php

require\_once 'sentinel.php';

Sentinel::init('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key');

Sentinel::check(); // blocks malicious requests automatically

```



\## JavaScript / Express



```javascript

const sentinel = require('./sentinel');

sentinel.init('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key');

app.use(sentinel.middleware()); // protects every route

```



\## Python / Flask



```python

from sentinel import Sentinel

sentinel = Sentinel('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key')



@app.before\_request

def protect():

&#x20;   result = sentinel.check\_flask\_request(request)

&#x20;   if result\['decision'] == 'block':

&#x20;       return jsonify({'error': 'Blocked'}), 403

```



\## Python / Django



Add to `settings.py`:

```python

SENTINEL\_API\_URL = 'https://sentinel-ai-3xkl.onrender.com'

SENTINEL\_API\_KEY = 'sk-your-key'

MIDDLEWARE = \['path.to.SentinelMiddleware', ...existing middleware...]

```

