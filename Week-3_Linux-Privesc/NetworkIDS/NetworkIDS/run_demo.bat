@echo off
REM Demo runner: process normal and attack PCAPs, write alerts to alerts.log
setlocal
IF NOT EXIST "venv" (
    echo Tip: Consider using a virtualenv. Skipping automatic creation to keep things simple.
)
echo === Running demo on sample_normal.pcap ===
python src\main.py --pcap src\tests\sample_normal.pcap --log alerts.log
echo.
echo === Running demo on sample_attack.pcap ===
python src\main.py --pcap src\tests\sample_attack.pcap --log alerts.log
echo.
echo Done. See alerts.log
endlocal