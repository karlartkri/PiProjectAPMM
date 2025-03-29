# Pi Zero W Controller

En robust och pålitlig WiFi-kontroller för Raspberry Pi Zero W som hanterar hotspot och monitor mode utan externa verktyg.

## Funktioner

- **Hotspot-hantering**
  - Skapar en WiFi-hotspot med anpassad SSID och lösenord
  - Hanterar klientanslutningar och DHCP automatiskt
  - Kontinuerlig beacon-transmission för stabil anslutning

- **Monitor Mode**
  - Aktiverar monitor mode för WiFi-analys
  - Kan köras samtidigt som hotspot
  - Detaljerad loggning av WiFi-ramar

- **Systemövervakning**
  - Kontinuerlig övervakning av systemtillstånd
  - Automatisk återställning vid problem
  - Övervakning av CPU och minnesanvändning

- **Backup & Återställning**
  - Automatisk backup av kritiska systemfiler
  - Backup var 24:e timme
  - Behåller de 5 senaste backuperna
  - Enkel återställning från backup

- **Felhantering**
  - Automatisk återställning vid kritiska fel
  - Detaljerad loggning av alla fel
  - Verifiering av systemtillstånd före och efter operationer

## Systemkrav

- Raspberry Pi Zero W
- Python 3.7+
- Root-behörighet
- Raw socket-stöd

## Installation

1. Klona repot:
```bash
git clone https://github.com/yourusername/PiProject.git
cd PiProject
```

2. Installera beroenden:
```bash
pip install -r requirements.txt
```

3. Kör programmet:
```bash
sudo python3 app.py
```

## Användning

Programmet startar med en färgkodad terminalmeny:

1. **Toggle Hotspot** - Startar/stoppar WiFi-hotspot
2. **Toggle Monitor Mode** - Aktiverar/inaktiverar monitor mode
3. **Show Log** - Visar senaste loggmeddelanden
4. **System Backup** - Skapar manuell backup
5. **Restore System** - Återställer system från backup
6. **Exit** - Avslutar programmet

## Loggning

- Alla händelser loggas i `pi_controller.log`
- Färgkodad loggning i terminalen:
  - 🔴 ERROR/CRITICAL
  - 🟡 WARNING
  - 🟢 INFO
  - ⚪ Övrigt

## Felhantering

Systemet har flera nivåer av felhantering:

1. **Automatisk återställning**
   - Återställer tjänster vid mindre problem
   - Verifierar systemtillstånd efter återställning

2. **Full systemåterställning**
   - Återställer från senaste backup vid kritiska fel
   - Verifierar systemtillstånd efter återställning

3. **Nödåtgärder**
   - Skapar nödbackup vid kritiska fel
   - Stoppar tjänster på ett säkert sätt
   - Återställer nätverksgränssnitt

## Vanliga problem

1. **Hotspot försvinner**
   - Kontrollera loggfilen för felmeddelanden
   - Systemet försöker automatiskt återställa
   - Om problemet kvarstår, återställ från backup

2. **Monitor mode fungerar inte**
   - Verifiera att gränssnittet är tillgängligt
   - Kontrollera systemloggar
   - Prova att starta om systemet

3. **Högt CPU/minnesanvändning**
   - Systemet varnar vid >90% användning
   - Automatisk återställning vid problem
   - Kontrollera loggarna för detaljer

## Säkerhet

- Alla kritiska operationer kräver root-behörighet
- Säker hantering av nätverksgränssnitt
- Backup av systemfiler innan ändringar
- Verifiering av systemtillstånd

## Bidra

1. Forka repot
2. Skapa en feature branch
3. Commita dina ändringar
4. Pusha till branchen
5. Skapa en Pull Request

## Licens

Detta projekt är licensierat under MIT-licensen - se [LICENSE](LICENSE) för detaljer. 