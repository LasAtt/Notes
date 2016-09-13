2016-09-13 oha luento 3
=======================

###Päivän oppimistavoitteet

* Arkkitehtuurin hyödyt ja käyttö
* Kuinka paljon arkkitehtuuria?
* Ohjelmistoarkkitehdin tiedot ja taidot
* Arkkitehtuuri ohjelmistokehitysprosessissa

##Ratkaisu - iteratiivisuus

* Jokaiseen iteraatioon analyyysi, arvioidaan projetktin tavoitteiden saavuttamista ja suunnittelua

###Ketterä arkkitehtuuri
* Alistair Cockburn, ketterän kehityksen isä
 * Walking Skeleton 
 * Incremental Rearchitechture

##Inkrementaalinen kehitys
* Vesiputousmalli ongelmallinen -> kehitetty inkrementaalisia tapoja ohjelmistokehitykseen
 * Astettaista kasvattamista korostavia prosessimalleja:
  * Spiral model
  * RUP
  * Risk-driven approach

###Spiraalimalli
* Metaprosessimalli projektikohtaisen kehitysmenetelmän löytämiseksi
* Syklikehitys
 1. projektin menestymisen kannalta kriittisten sidosryhmien tavoitteiden selvitys
 2. riskintunnistus, kehitetään ja evaluoidaan vaihtoehtoisia ratkaisuja
 3. kehitetään ja testataan ratkaisu
 4. hankitaan sidosryhmien hyväksyntä ja lupa siirtyä seuraavaan vaiheeseen
* Projekti voi yhdistellä soia eri kehitysmenetelmistä sillä perusteella miten ne sopivat projektin riskien voittamiseen
 * Eri sykleissä ehkä eri menetelmä
* [](https://en.wikipedia.org/wiki/Spiral_Model)
* Life Cycle Architecture -kontrollipiste
 * Onko olemassa ratkaisua joka eliminoi riskit/täyttää tavoitteet
 * On haitallisia spiraalimaisia malleja, jotka jättävät huomiotta evolutionaarisen mallin ja käyttävät runsaasti aikaa huonon ratkaisun toteutukseen

###Rational Unified Process
* Räätälöivä prosessikehys iteratiiviseen ohjelmistokehitykseen
 * Neljä peräkkäistä vaihetta, kiinteän mittaiset iteraatiot joilla tuotetaan lisäarvoa (business value)
 * Kussakin vaiheessa ja iteraatiossa kaikkia ohjelmistokehityksen tapoja
 * Pidemmät iteraatiot kuin yleensä (kuukausia)
* Arkkitehtuurityö 'Elaboration'-vaiheessa

###Fairbanks - Risk-driven approach
* Idea 
 * Arkkitehtuuria vain sen verran kuin riskien voittaminen vaatii
* Riskit voivat liittyä ohjelmiston käyttöön ja sen laatuominaisuuksiin (tuoteriski)
 * Korkea suorituskyky, turvallisuus, skaalautuvuus, jne
* .. tai sen kehitykseen (projektiriski)
 * teknologiat, henkilöstön määrä ja osaaminen, asiakas, aikataulu, työkalut
* Kysytään, "Mikä voi mennä pieleen ohjelmistoa käytettäessä ja kehitettäessä?"

####Riski
Asiaan A liittyvä Riski = häiriön tod.näk A:ssa, x häiriön aiheuttama haitta

* Riskien tunnistus lähtökohta:
 * Ei aina helppoa, vaatii kokemusta sovellusalueesta ja teknologioista
 * vaaimukset hyvä lähtökohta 
  * Vaikeasti toteutettavat asia
  * Tunnistamattomat tai epäselvät vaatimukset voivat olla riskinaiheuttajia

#####Yleisiä riskikategorioita

Sovellusalue | Tyypillinen riski
--- | ---
Tietotekniikkapalvelut | kompleksinen / huonosti ymmärretty / väärät cots-ongelmat / ongema-alue / epävarmuus ongelmasta / integrointi / huono tuntemus sovellusalueesta/ muunneltavuus
Kriittiset järjestelmät | Suorituskyky, luotettavuus, koko, turvallisuus / Rinnakkaisuus / Koostaminen ja konfigurointi
Web | Turvallisuus / Skaalautuvuus käyttäjämäärän ja datamäärän mukaan / Kehittäjien luotettavus

#####Riskinhallinta
* Tunnistetut riskit pitää kirjoitttaa auki
 * Näin voidaan todeta ovatko riskin pienennystoimet tehokkaita
 * Kirjoitetaan häiriöskenaario, jossa häiriötilanne kuvataan _kvantitatiivisesti_
  * Esim. aloitussivun lataaminen kestää >10s 10% käyttäjistä
* Perusidea
 1. Tunnista ja priorisoi riskit
 2. Valitaan sopivat tekniikat riskien lieventämiseen
 3. Evaluoi toimenpiteiden viakutus riskeihin
* Sykliä toistetaan kunnes riskit siedettävällä tasolla

###Risk-driven approach
* Ei kaiken-kattava prosessimalli vaan kokoelma tekniikoita
* Ei edellytä kehitysprosessia
 * RUP ja spiraalimalli prosessit myös riskilähtöisiä (Most risky things first)
 * Sopii ohjenuoraksi ketterään kehitykseen, joskin niissä fokus käyttäjälle näkyvä toiminnallisuus

##Yhteenveto
* Arkkitehtuurityötä voidaan tehdä monenlaisissa projekteissa
* Oikea malli valittava projektin koon, tarpeiden ja mahdollisten riskien mukaan
* Riskinhallinta 

#Luento osa 2

##Ohjelmistoarkkitehtuuritiedon lähteillä
* Yhdellä kurssilla ei kenestäkään arkkitehtia
* Arkkitehdiksi kokemuksen kautta
* Muitten kokemuksista voi ottaa oppia ja kehittää taitoja
 * Tyylit- ja patternit
 * Yleiset suunnitelluperiaatte
 * Laatuominaisuuksia Suunnitelutaktiikat
 * Kokemusraportit ja kuvaukset onnistuneista ja epäonnistuneista ratkaisuista

###Referenssejä
* High scalability -sivusto
 * http://highscalability.com
* Handbook of Software Architecture

##Arkkitehtuurityylit- ja patternit

###Arkkitehtuurityyli
* Nimetty kkokoelma tiettyyn käyttöyhteyteen soveltuvia yleisia suunnitteluperiaatteita ja sääntöjä jotka tuovat hyödyllisiä ominaisuuksia rakennettavaan järjestelmään
 * Esim. asiakas - palvelin tyyli (Client-Server):
  * Erotelllaan palvelun pyytävä ja palvelun tarjoava ohjelmistokomponentti
  * Piilotetaan palvelua pyytävien komponenttien identiteetti palvelun tarjoajalta ja mahdollistetaan useiden pyytäjien mahdollisesti vaihtelevan joukon paveleminen
  * Pyytäjien eristys
  * Palveluntarjoajien määrän muuttaminen tarpeen vaatiessa

###Arkkitehtuuripatterni (tai -malli)
* Nimetty kokoelma johonkin toistuvaan suunnitteluongelmaan soveltuvia suunnitteluratkaisuja, jotka parametrisoitu ottamaan huomioon käyttöyhteys jossa ongelmaa esiintyy
* Miten tyyli eroaa patternista
 * Käyttötilanne yleisempi tyylillä, patternilla spesifimpi, konkreettisempi
 * Tyylit periaatesääntöja ja patternit konkreettisia ratkaisuja
 * Patternit soveltavat tyyliä
 * Kaikki lähteet eivät erota käsitteitä

###Tyyli ja patterni
* Esimerkki:
  * Kolmitasoarkkitehtuuri -patterni

###Tyylien käytöstä
* Muitten jälkittely ja suunnittelun uudelleenkäyttö on hyvä oppimismenetelmä

##Yleiset suunnitteluperiaatteet

* Abstraction, Encapsulation, Information Hiding, Modularization, Speration of Concerns, Coupling and Cohesion, Sufficiency-Completeness

###Information Hiding
* Ohjelmisto jaetaan moduuleihin siten, että kukin moduuli kätkee jonkin todennäköisesti muuttuvat teknisen tai sovellusalueen piirteen toteutuksen (=suunnittelupäätökset)
* Moduuli tarjoaa palveluihinsa vakaan abstraktin rajapinnan, joka ei paljasta toteutuksen yksityiskohtia (ns. abstrakti tietotyyppi)
* Esim. Javan Interfacejen käyttö
 * Kentät merkitään yksityisiksti, mutta määritellään niile julkiset get()- ja set()- metodit
* Harvempi tulee ajatelleeksi odotettavissa olevia muutoksia ja muuteosten heijastusvaikutusten ennalta ehkäisemistä ohjelmiston modularisoinnin avulla
 * Arkkitehdin työn kuvaan tälläisen ajatteleminen kuitenkin kuuluu

###Separation of Concerns
* ERilaiset tai yhteenkuulumattomat vastuut eriytetään ohjelmistossa 
 * Jaetaan eri komponenteille yksi oma vastuu = Single Responsibility -periaate
* Vastuu: jotakin mitä komponentti tekee tai tietää tai piilottaa muilta (toiminto, riippuvuus, data, ...)
* Tietyn tehtävän yhteistyössä suorittvat komponentit erillään muista komponenteista
* Jos komponenteilla useita rooleja eri tilanteita varten, pidetään roolit erillään myös komponentin sisällä

###Coupling (kytkentä
* Moduulien vqlisen assosiaation voimakkuuden mittari
 * Voimakas kytkentä moduulien välillä tekee niistä vaikeammin ymmärrettäviä, muutettavia ja korjattavia toisistaan riippumatta
 * Esim. A ja B luokat naimisissa, A:n muutokset heijastuvat B:n muutostarpeisiin
* Mittarille on tekinen määritelmä, mutta asian ydin on heijastusvaikutusten hillitseminen moduuleita muutettaessa

###Ortognaalisuus
* Suunnittelussa ja arkkitehtuurissa
 * moduulien ja komponettien välisen keskinäisen riippumattomuuden mitta

###Cohesion
* Koheesiomittari, yhteenkuuluvuuden mittari
* Yhteenkuuluvuuden eri asteita
 * Toiminnallinen (hyvä): kaikki moduulin elementit toimivat yhdessä jonkin tiety, rajallisen tehtävän toteuttamiseksi
 * Sattumanvarainen (huono): moduuli satunnainen kokoelma yhteenkuulumattomia abstraktioita ja toimintoja
* Asteita muitakin mutta oleellista miettiä mikä moduulin päätehtävä ja miten sen elementit liittyvät tuon tehtävän suorittamiseen
 * Voiko jotkut elementit siirtää pois moduulista sen päätehtävän toteuttamisen kärsimättä

##Järjestelmän jakaminen osiin

**Kuinka syödä elefantti?**
* Jaetaan osiin!

###Kokonaisuus koostuu osista
* Oletusarkkitehtuuri antaa valmiin "kaavan" jolla tehdään ositus loogisesti ja fyysisesti erilaisiin komponentteihin
* Arkkitehtuurityylit- ja patternit tarjoavat suoraan lähtökohtia suunnitteluun ja ositukseen
* Yleiset suunniteluperiaatteet antavat ohjenuoria ja mittareita ositukseen ja sen arviointiin
* Mitä muita yleisiä tapoja suorittaa ositus?

####Ositusstrategiat
* Divide & Conquer
 * hierarkisuus, komponenttien kokotasolla tarkastellaan järjestelmää, välittämättä sisäisestä rakenteesta
* Sama rekursiivisesti alemmilla tasoilla

####Fairbanksin esittämä
1. muodosta abstraktioiden hierarkia
2. rajoita elementtien määrä kullakin tasola 
3. jokaisella elementillä tarkoitus
4. tiedon kapselointi

###Ositusstrategiat
* **Jako toiminallisuuden mukaan**
 * Yhteenkuuluva toiminllisuus samaan elementtiin
* **Jako arkkittyyppien mukaan**
* **Jako arkkitehtuurityylin mukaan**
* **Jako tiettyjen laatuvaatimusten saavuttamiseen tähtäävien suunnittelutaktiikoiden perusteella**
 * Quality Attribute Driven Design
 * Eri laatuattribuuteille omat taktiikkansa
* **Jako järjestelmän tarjoamien palvelujen mukaan**
 * Jokaista palvelua ja rajapintaa kohden yksen implementoiva komponentti
* **Palapeli**
 * Kokonaisuus sovitellaan jo olemassaolevista elementeistä erilaisilla sovittimilla ja "liimakomponenteilla
 * Yleinen ratkaisu yritysjärjestelmissä, jossa ei aloiteta puhtaalta pöydältä
* **Ongelman uudelleenmuotoilu toisen sovellusalueen käsittein ja valmiin osituksen käyttö**

