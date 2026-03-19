@echo off
setlocal EnableExtensions
REM =============================================================================
REM Dijital Iz Surucu — Windows tek komut calistirici
REM Velociraptor felsefesi: tek giris noktasindan tum kanallar (Disk/EVTX, RAM,
REM Ag PCAP, onceden uretilmis Bulut/Mobil JSON) — kullanici klasoru surukler,
REM script main.py'yi uygun bayraklarla otomatik baslatir.
REM =============================================================================
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo ========================================================================
echo   DIZ RUN — Analiz klasorunu surukleyin veya yolu yapistirin
echo   (Disk/EVTX + varsa RAM imaji, PCAP, cloud/mobile JSON)
echo ========================================================================
echo.
echo Lutfen analiz edilecek klasoru bu pencereye surukleyip birakin,
echo      ardindan Enter'a basin — veya tam yolu yazip Enter:
echo.

set "TARGET="
set /p "TARGET=Klasor yolu: "
if not defined TARGET (
  echo [!] Klasor yolu gerekli.
  exit /b 1
)

set "TARGET=%TARGET:"=%"

if not exist "%TARGET%" (
  echo [!] Yol bulunamadi: %TARGET%
  exit /b 1
)

if not exist "data\results" mkdir "data\results"

if exist "%TARGET%\cloud_findings.json" (
  copy /Y "%TARGET%\cloud_findings.json" "data\results\" >nul
  echo [+] cloud_findings.json — data\results
)
if exist "%TARGET%\mobile_findings.json" (
  copy /Y "%TARGET%\mobile_findings.json" "data\results\" >nul
  echo [+] mobile_findings.json — data\results
)

set "MEM_PATH="
for %%e in (raw dmp vmem mem) do (
  if not defined MEM_PATH (
    for %%F in ("%TARGET%\*.%%e") do if exist "%%~fF" set "MEM_PATH=%%~fF"
  )
)

set "PCAP_PATH="
for %%e in (pcap pcapng cap) do (
  if not defined PCAP_PATH (
    for %%F in ("%TARGET%\*.%%e") do if exist "%%~fF" set "PCAP_PATH=%%~fF"
  )
)

set "PY=python"
where python >nul 2>&1 || set "PY=py"

set "REPORT=data\results\diz_report.html"

echo.
echo [*] Girdi: %TARGET%
if defined MEM_PATH echo     --memory %MEM_PATH%
if defined PCAP_PATH echo     --pcap %PCAP_PATH%
echo     --report %REPORT%
echo.

if defined MEM_PATH (
  if defined PCAP_PATH (
    "%PY%" -u main.py --input "%TARGET%" --report "%REPORT%" --memory "%MEM_PATH%" --pcap "%PCAP_PATH%"
  ) else (
    "%PY%" -u main.py --input "%TARGET%" --report "%REPORT%" --memory "%MEM_PATH%"
  )
) else (
  if defined PCAP_PATH (
    "%PY%" -u main.py --input "%TARGET%" --report "%REPORT%" --pcap "%PCAP_PATH%"
  ) else (
    "%PY%" -u main.py --input "%TARGET%" --report "%REPORT%"
  )
)

set "EC=%ERRORLEVEL%"
echo.
if %EC% neq 0 (
  echo [!] main.py cikis kodu: %EC%
) else (
  echo [+] Tamam. Rapor: %REPORT%
)
exit /b %EC%
