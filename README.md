# Wifty

### Just A Wyze <> IFTTT Synchronization Service.

I wrote this to simply help keep my Wyze <> IFTTT connection synchronized. Occasionally I will find that IFTTT cannot detect my Wyze cams. This is solved by just logging back into IFTTT and connecting Wyze again. If Wyze ever opens up their cameras with a Developer SDK, I plan to update Wifty to serve as my own Wyze <> IFTTT bridge. For now it serves one single purpose.

Wifty utilize chromedriver to handle the web automation aspects, and simply stores your settings in an encrypted file under `wifty.json.enc`

### System Requirements
- Apache Maven
- JDK 8+
- Linux or Mac OSX

### Starting Wifty

```bash
git clone https://github.com/TonyRice/wifty.git
cd wifty

mvn compile exec:java
```

Note: Wifty is designed to be running continiously, and utilizes Chromedriver with Chrome in headless mode.
