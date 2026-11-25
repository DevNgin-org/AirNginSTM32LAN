# AirNginSTM32LAN

پورت آردوینوی STM32 برای ابزار AirNgin با اترنت W5100. نمونه برای NUCLEO-F401RE ساخته شده است.

## راه‌اندازی با اپ AirNgin

1. در PlatformIO همین پوشه را باز کنید. در Arduino IDE کتابخانه و وابستگی‌های فهرست‌شده در `library.properties` را نصب و مثال `LanUptime` را باز کنید.
2. در مثال، سریال ثبت‌شده و کد چهارحرفی تولیدکننده را جایگزین کنید. شیلد W5100 از SPI و پایهٔ انتخاب D10 استفاده می‌کند. D4 کارت SD را غیرفعال می‌کند. پایهٔ A0 را طبق نیاز SSLClient آزاد بگذارید. برد و تلفن باید در شبکه‌ای باشند که multicast بین آن‌ها برقرار است.
3. پس از DHCP، در اپ «افزودن ابزار» را باز کنید. برد با نام سرویس `_matterc._udp.local` و TXT شامل `sn=<serial>` دیده می‌شود. در پاسخ، IP دستگاه هم اعلام می‌شود. اپ همین مسیر را برای هر ابزار حاضر در شبکه، از جمله ابزار Wi-Fi با اتصال قبلی، استفاده می‌کند. در این مثال رابط شبکه W5100 است.
4. روی برد تازه، دریافت تنظیمات برای سه دقیقه باز می‌شود. برای بازکردن مجدد یا تغییر پروژه، دکمهٔ کاربر (PC13) را سه ثانیه نگه دارید. اپ تنظیمات را با `GET http://<device-ip>/set?data=<encoded-json>` می‌فرستد. پاسخ موفق پس از ذخیره و بازخوانی پروفایل صادر می‌شود. رمز Wi-Fi برای این مسیر لازم نیست. کشف mDNS پس از بسته‌شدن پنجره نیز ادامه دارد.
5. عملیات عددی `uptime_seconds` را برای ابزار تعریف کنید. بعد از دریافت زمان UTC و تأیید TLS و اشتراک فرمان، نمونه هر ۳۰ ثانیه کارکرد برد را با QoS 1 می‌فرستد. مانیتور سریال را روی 115200 باز کنید. تأیید MQTT و نمایش در پنل دو مرحلهٔ مجزا هستند.

## LAN and cloud contracts

- The older STM32 library supplies the LAN discovery and setup convention. In the setup window, UDP 45454 broadcasts `DVC-<serial>-key`, IP, gateway, subnet, DNS and serial. Legacy clients may send START, STOP, FINISH or profile JSON. UDP/HTTP provisioning carries credentials on the local network. Use a trusted commissioning LAN.
- The mobile direct-LAN flow uses DNS-SD PTR/SRV/TXT/A discovery and HTTP on port 80. The device advertises its serial without the gateway-specific `gw` attribute. mDNS carries discovery information. Device operations use MQTT 3.1.1 over hostname-verified TLS on port 8883, using the current SDK's Certum trust anchor and the provisioned credentials.
- Telemetry and command replies publish to `<project>/DeviceToServer`. Incoming commands subscribe to `<project>/ServerToDevice/<serial>` at QoS 1. The command envelope and operation limits follow the current SDK. A command handler may provide a reply or return false to omit it.
- Optional application encryption uses the same AES-256-GCM envelope, device key, 60-second timestamp window, replay checks and `/AES` suffix as the ESP SDK. Pass a cryptographically secure `RandomBytes` function to `begin` to select this build's AES behavior. Supply a board RNG or external secure element appropriate to the product. The example uses TLS with the PLAIN application payload. The configured mode must match provisioning. The example's A0 analog input is for SSLClient and is not an application AES nonce source.
- `followTime` subscribes to the UTC or Tehran time feed at QoS 0. Read parsed records with `latestTime`. Public time topics remain unsuffixed. `notify` supports center, SMS and push notifications with the SDK's MQTT channel and payload conventions.
- The library owns the setup and MQTT sockets. Reserve the profile region at the selected EEPROM offset and the STM32 core's emulated EEPROM flash sector. A failed integrity check returns the device to commissioning. This layout is separate from the old firmware's stored profile. The optional HTTPS Cloud Database API is outside this LAN/MQTT port.

## Validation

Build with `pio run -e nucleo_f401re`. The tested setup uses STM32 Arduino core 3.0.0, PlatformIO ST STM32 20.0.0 and the dependency versions pinned in `platformio.ini`. Run the protocol fixtures with `tests/run.sh <path-to-SSLClient/src>`. They check discovery records, provisioning query decoding, app profile data, topic construction, addressed commands, time parsing and AES known-answer/rejection cases. Physical DHCP, phone discovery, MQTT delivery and power-cycle persistence still require an STM32 and an Ethernet shield.

The current protocol is derived from [AirNgin ESP32 SDK 1.6.1](https://github.com/DevNgin-org/AirNgin-Arduino/tree/v1.6.1). The LAN compatibility convention comes from [the original STM32 client](https://github.com/AirNgin/Airngin-stm32-mqtt-client). The bundled JSON parser is cJSON 1.7.19. See the included licenses.
