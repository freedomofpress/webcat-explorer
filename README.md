# webcat-explorer

A static explorer for the [WEBCAT](https://github.com/freedomofpress/webcat) enrollment list.

A daily CI job verifies the list the way the extension does, checks every enrolled site's bundle and signatures, scans the Sigsum logs, and writes `site/data.json`. The static app in `site/` renders that file.

```
npm ci
npm test
npm run build
```
