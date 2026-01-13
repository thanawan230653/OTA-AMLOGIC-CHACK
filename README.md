วิธีรัน (ตัวอย่าง Windows PowerShell)
1) ลอง Google OTA (ต้องอยู่ในโฟลเดอร์ google-ota-prober ที่มี probe.py)
python ota_try_get_link.py --build-prop C:\Users\COM\Desktop\build.prop --probe-py .\probe.py

2) ถ้าคุณมีโฟลเดอร์ ROM ที่แตกไว้ (สำคัญ)

สมมติแตกไว้ที่ D:\rom_extracted\ (ข้างในมี system/vendor/odm)

python ota_try_get_link.py --build-prop C:\Users\COM\Desktop\build.prop --rom-root D:\rom_extracted --open

3) ถ้าอยาก “สแกนหา URL อย่างเดียว” (ไม่ยิงเน็ต)
python ota_try_get_link.py --build-prop C:\Users\COM\Desktop\build.prop --rom-root D:\rom_extracted --dry-run

เรื่อง “เทสให้จนได้ลิงก์” (พูดตรง)

ผมสามารถเขียนและจัดโค้ดให้ดีที่สุดได้ (ทำให้แล้ว) แต่การ “รับประกันว่าต้องได้ลิงก์ OTA” จะเกิดขึ้นได้ก็ต่อเมื่อ:

มี OTA จริงบนเซิร์ฟเวอร์

และ ROM/แอปอัปเดตมี endpoint/URL ที่สแกนเจอ

วิธีรันอีกวิธี

python probe.py --fingerprint Nokia/SEI600NK/HND:10/QTT8.201201.002/1801:user/release-keys
Update title: New SW version is available
OTA URL obtained: https://android.googleapis.com/packages/ota-api/package/52782c0413cdea4d36ebb591b31409cbac8b4b2a.zip

และ endpoint นั้นเข้าถึงได้จากคอมของคุณ

ถ้ารันแล้วไม่เจอ ให้คุณส่ง ผลลัพธ์ส่วนนี้ มา:

รายการ “candidate URL(s)” ที่มันพิมพ์ออกมา
