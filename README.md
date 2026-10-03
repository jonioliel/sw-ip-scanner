# IP Scanner for Home Assistant

[![Validate app](https://github.com/jonioliel/sw-ip-scanner/actions/workflows/validate.yml/badge.svg)](https://github.com/jonioliel/sw-ip-scanner/actions/workflows/validate.yml)

תוסף מקומי ל־Home Assistant OS שמציג את רשת ה־IPv4 שאליה מחובר השרת, דרך Ingress בתוך Home Assistant.

## התקנה דרך חנות התוספים

1. פתח **הגדרות → Apps / תוספים → חנות**.
2. בתפריט ⋮ בחר **Repositories / מאגרים** והוסף:

   ```text
   https://github.com/jonioliel/sw-ip-scanner
   ```

3. סגור את החלון ורענן את החנות. בחר **IP Scanner** מתוך המאגר החדש ולחץ **התקנה**.
4. הפעל את התוסף ובחר **הצג בסרגל הצד** או **פתח ממשק Web**.

אפשר גם להתחיל דרך [הוספת המאגר ל־Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fjonioliel%2Fsw-ip-scanner).

הבנייה מתבצעת על שרת HA בהתקנה הראשונה ודורשת חיבור לאינטרנט. אין צורך להעתיק קבצים ידנית במסלול ההתקנה הזה. פירוט ההגדרות נמצא ב־[תיעוד התוסף](ip_scanner/DOCS.md).

## מה כבר יש

- זיהוי אוטומטי של ממשק הרשת והטווח; בחירה בין רשתות מקומיות המחוברות לשרת.
- סריקת ARP עם Nmap, בלי סריקת פורטים.
- שמות DNS ושמות mDNS כשמכשירים מפרסמים אותם, יצרן ו־MAC כשזמינים.
- טבלת מכשירים, טבלת כתובות פנויות לכאורה וטבלת טווחים רציפים.
- מפת כתובות שאפשר ללחוץ עליה, חיפוש, סינון, עימוד וייצוא CSV.
- שמות מותאמים, היסטוריה שנשמרת בהפעלה מחדש וסריקה מחזורית.
- ממשק בעברית, התאמה לטלפון, מצב בהיר וכהה.

**הסטטוס: גרסת 0.1.0 ניסיונית מוכנה להתקנה לבדיקה.** עברו 16 בדיקות לוגיקה ו־API ובדיקות ממשק ההדגמה. ב־GitHub Actions עברו גם הבדיקות על Linux ובניית Docker ל־amd64 ול־aarch64. סריקה אמיתית והפעלת Ingress על Home Assistant OS עדיין דורשות אימות על שרת HA. [תוצאות הבדיקות והבנייה](https://github.com/jonioliel/sw-ip-scanner/actions/workflows/validate.yml).

## התקנה מקומית

1. חלץ את `output/ip-scanner-addon-0.1.0.zip`.
2. העתק את התיקייה `ip_scanner` במלואה אל `/addons/ip_scanner` בשרת Home Assistant, באמצעות כלי הגישה שלך, למשל Samba או SSH. אין להעתיק אל `/config/custom_components`.
3. ב־Home Assistant פתח **הגדרות → Apps / תוספים → חנות** ובתפריט ⋮ בחר **בדיקת עדכונים** / **Check for updates**.
4. תחת **Local apps / Local add-ons** בחר **IP Scanner** ולחץ **התקנה**. הבנייה הראשונה מורידה את התלויות ודורשת חיבור לאינטרנט.
5. הפעל את התוסף, בחר **הצג בסרגל הצד** ופתח את ממשק ה־Web.

התצורה הראשונית מזהה את הרשת וסורקת אותה אוטומטית; בדרך כלל אין צורך להזין טווח IP. פירוט ההגדרות והפתרון לתקלות נמצא ב־[`ip_scanner/DOCS.md`](ip_scanner/DOCS.md).

## מה פירוש המצבים

| מצב | משמעות |
| --- | --- |
| תפוסה | זוהתה תגובה בסריקה האחרונה שהושלמה בהצלחה. |
| נראתה בעבר | הכתובת זוהתה בעבר, אך לא ענתה בסריקה האחרונה. אינה נספרת כפנויה. |
| פנויה לכאורה | הכתובת לא זוהתה בסריקה האחרונה ואין לה זיהוי בהיסטוריית הטווח. |
| טרם נסרקה | אין סריקה מוצלחת לטווח. לא מסיקים דבר על זמינות הכתובות. |

סריקה אינה קוראת את טבלת ההקצאות של הנתב. כתובת שלא עונה יכולה להיות שמורה ב־DHCP או שייכת למכשיר כבוי; לפני הקצאה קבועה יש לבדוק גם בנתב. כתובות הרשת והשידור מוחרגות מהטבלאות. ההיסטוריה נשמרת לפי טווח וכתובת, ושמות מותאמים משויכים לכתובת IP.

## הדמיה

פתח `output/ip-scanner-demo.html` בדפדפן. אין חיבור לרשת ואין סריקה אמיתית במצב הזה. המסך משתמש באותו ממשק כמו התוסף, עם 18 מכשירים לדוגמה, 3 כתובות שנראו בעבר ו־233 כתובות פנויות לכאורה. בדיקות הממשק עברו גם על הקובץ העצמאי וגם מול API ההדגמה.

אפשר גם להפעיל API מקומי לדוגמה:

```powershell
python ip_scanner/app/app.py --demo --data output/demo-data --port 8099
```

ואז לפתוח `http://127.0.0.1:8099`. מצב ההדגמה מופעל רק עם `--demo`; התוסף המותקן אינו מפעיל אותו.

## פיתוח ובדיקות

```powershell
python -m unittest discover -s tests -v
python tools/build_preview.py
node tools/check_ui.cjs
python tools/package_addon.py
```

בדיקות הממשק דורשות Playwright ודפדפן זמין. ניתן להגדיר `SCANNER_BROWSER` לנתיב של Chrome / Chromium. אין תלויות Python לצורך הבדיקות או ההדמיה; `zeroconf` מותקן בתוך התוסף עבור mDNS.

## גבולות הגרסה

- IPv4, רשתות מקומיות המחוברות ישירות, עד 4,094 כתובות לטווח (‎/20–‎/30). IPv6 אינו ממופה לכתובות פנויות.
- רשתות VLAN נפרדות יופיעו רק אם יש לשרת ממשק מחובר אליהן. תוסף ברשת אחת אינו רואה אוטומטית רשתות אחרות מאחורי נתב.
- שם מכשיר מופיע רק אם יש DNS/mDNS או שם מותאם. אין אפשרות להסיק בוודאות את שם כל רכיב באמצעות כתובת MAC.
- כתובת שמורה ב־DHCP אינה מזוהה בלי שילוב ייעודי עם הנתב. זהו שלב הרחבה עתידי, בהתאם לדגם הנתב.
- הגישה בייצור מותרת רק לכתובת ה־Ingress של Supervisor. אין ממשק Web פתוח ישירות לכל הרשת ואין צורך לבטל Protected mode.

## מקורות לפיתוח

- [Home Assistant: App configuration](https://developers.home-assistant.io/docs/apps/configuration/)
- [Home Assistant: Ingress communication](https://developers.home-assistant.io/docs/apps/communication/)
- [Home Assistant: Local testing](https://developers.home-assistant.io/docs/apps/testing/)
- [Nmap: Host discovery and ARP](https://nmap.org/book/man-host-discovery.html)
- [python-zeroconf: API](https://python-zeroconf.readthedocs.io/en/latest/api.html)
