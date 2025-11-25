import cv2, time
cap = cv2.VideoCapture(0)
if not cap.isOpened():
    raise SystemExit('Cannot open camera')
while True:
    ret, frame = cap.read()
    if ret:
        cv2.imwrite('latest.jpg', frame)
    time.sleep(0.5)
