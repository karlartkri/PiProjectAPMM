# Pi Zero W Controller

En Python-applikation för att hantera WiFi hotspot och monitor mode på Raspberry Pi Zero W, implementerad med raw sockets för full kontroll över nätverkskommunikationen.

## Funktioner

- WiFi hotspot utan externa verktyg
- Monitor mode-stöd
- Terminal-baserat gränssnitt
- Detaljerad loggning och felhantering
- Automatisk felåterställning
- DHCP-server implementation
- Raw socket-baserad nätverkskommunikation

## Systemkrav

- Raspberry Pi Zero W
- Python 3.x
- Root-behörighet (sudo)
- Linux-kernel med raw socket-stöd
- Nätverksgränssnitt som stödjer monitor mode

## Installation

1. Klona repot:
```bash
git clone https://github.com/yourusername/pi-project.git
cd pi-project
```

2. Installera nödvändiga paket:
```bash
pip install -r requirements.txt
```

3. Kör applikationen med root-behörighet:
```bash
sudo python3 app.py
```

## Användning

Applikationen erbjuder ett terminal-baserat gränssnitt med följande alternativ:

1. Toggle Hotspot - Starta/stoppa WiFi hotspot
2. Toggle Monitor Mode - Aktivera/inaktivera monitor mode
3. Show Log - Visa senaste loggposter
4. Exit - Stäng av programmet

## Loggning och Felhantering

### Loggfiler

Applikationen sparar detaljerade loggar i `pi_controller.log` med följande information:

- Tidsstämpel
- Loggningsnivå (DEBUG, INFO, ERROR, CRITICAL)
- Fil och radnummer
- Detaljerat meddelande
- Stack traces för fel

### Loggningsnivåer

- **DEBUG**: Detaljerad frame-information, systemtillstånd
- **INFO**: Normal drift, klientanslutningar
- **ERROR**: Icke-kritiska fel, återförsök
- **CRITICAL**: Systemfel, återställningsförsök

### Felåterställning

Systemet inkluderar automatisk felåterställning:

- Spårar fel inom ett 60-sekunders fönster
- Startar om tjänster automatiskt efter 5 konsekutiva fel
- Återställer nätverksgränssnitt vid behov
- Stängs av snyggt vid kritiska fel

### Vanliga Problem och Lösningar

1. **AP Försvinner Efter 15 Sekunder**
   - Kontrollera loggfilen för beacon-transmissionsfel
   - Verifiera gränssnittskonfigurationen
   - Övervaka felräkning i loggarna

2. **Monitor Mode Fungerar Inte**
   - Kontrollera gränssnittsbehörigheter
   - Verifiera raw socket-stöd
   - Granska fel i loggarna

3. **Klientanslutningsproblem**
   - Kontrollera DHCP-serverloggar
   - Verifiera beacon-frame-transmission
   - Övervaka autentisering/association

## Felsökning

### Visa Loggar i Realtid

```bash
tail -f pi_controller.log
```

### Kontrollera Systemtillstånd

```bash
# Kontrollera gränssnittsstatus
ifconfig wlan0

# Kontrollera systemloggar
dmesg | grep wlan0
```

### Vanliga Felmeddelanden

1. **"System requirements not met"**
   - Verifiera root-behörigheter
   - Kontrollera raw socket-stöd
   - Granska kernel-konfiguration

2. **"Failed to configure interface"**
   - Kontrollera gränssnittsbehörigheter
   - Verifiera nätverkskonfiguration
   - Granska systemloggar

3. **"Error threshold reached"**
   - Kontrollera felmönster i loggarna
   - Verifiera systemresurser
   - Granska nätverkskonfiguration

## Bidra

1. Forka repot
2. Skapa din feature-branch
3. Commita dina ändringar
4. Pusha till branchen
5. Skapa en ny Pull Request

## Licens

Detta projekt är licensierat under MIT-licensen - se LICENSE-filen för detaljer. 