# matchacloud.nl

Statische website, gehost via GitHub Pages.

## Structuur

- `index.html` – homepage
- `404.html` – foutpagina
- `css/style.css` – opmaak
- `assets/` – afbeeldingen en icoon
- `CNAME` – custom domein (`matchacloud.nl`)

## Lokaal bekijken

```bash
python3 -m http.server 8000
```

Open daarna http://localhost:8000.

## Publiceren

Elke push naar `main` wordt automatisch live gezet (Settings → Pages → Deploy from branch → `main` / root).

## DNS voor matchacloud.nl

Bij je domeinregistrar:

- `A`-records voor `@` naar `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
- `CNAME` voor `www` naar `matchacloudnl.github.io`

Zet daarna in Settings → Pages "Enforce HTTPS" aan.
