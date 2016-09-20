Oha luento 5 2016-09-20
=======================

##Arkkitehtuurityylejä


###Oppimistavoitteet

* Arkkitehtuurityylejä
 * Microservices, viestinvälitysarkkitehtuurit, vertaisverkkoarkkitehtuuri, cloud,

###Microservices
* Nousussa oleva, täsmentymätön tyyli
 * Vs. N-tier, vähemmän raskas ja monoliittinen
 * Tukee Continuous X 0käytäntöjä (integration, deployment, etc.)
* Unixin pipes and filters ajattelutapa sovellettuna palvelujen toteuttamiseen

* Perusidea: palvelinsopimus
 * Kokoelma pieniä, erillisiä palveluita
 * Jokaista palvelua ajetaan omassa prosessissaan
 * Palvelut kommunikoivat kevyitä mekanismeja käyttäen, esim. HTTP resurssi-API:eja
* Palvelu
 * osituksen perusteena liiketoimintaprosessit - ja toiminnot (single responsibility principle)
 * voidaan ottaa käyttöön itsenäisesti ja automaattisesti
* Minimimäärä palvelujen keskitettyä hallinnointia
 * Palvelujen toteutus mahdollista eri ohjelmointikielillä ja kirjastoilla
 * Palvelut voivat käyttää omia tiedonhallintaratkaisujaan
 * Hyvä skaalautuvuus (+ ja -) tavoitteena
* Transaktioiden sijaan tarvitaan toisenlaisia menetelmiä tiedon eheyden takaamiseen
 * Orkestrointi mikropalveluja käyttävien komponenttien vastuulla

* Etuja
 * Komponenttien päivitys helpottuu
 * Kuormittuessa voidaan helposti lisätä instansseja ja näin skaalata tehoa yksittäisille palveluille

###Viestinvälitysarkkitehtuurit
* Ongelma: miten toteutetaan asiakkaiden ja palvelujen välinen kommunikointi hajautetussa, heteroogeenisesä palveluympäristössä?
 * Monia eri ohjelmointikieliä ja toteutusteknologioita käytössä
 * Halutaan välttää suoran kommunikaation aiheuttamat suorituskyvyn pullonkaulat
 * Halutaan skaalautuvuutta jossa voidaan dynaamisesti lisätä ja vähentää palvelevia komponentteja
 * Halutaan löyhät kytkennät komponettien välille piilottamalla niiden toteutusteknologioiden yksityiskohdat (esim. ohjelmointikieli)
 * Halutaan joustavuutta ja ketteryyttä arkkitehtuuriin
 * Halutaan lisätä asynkronisuutta, jotta asiakkaan ei tarvitse jäädä odottamaan kun palvelin käsittelee pyyntöä, vaan se voi jatkaa muita toimintojaan j akäsitellä palvelimen lähettämän vastauksen sen valmistuttua
* Ratkaisu: komponentit kommunikoivat lähettqmällä toisilleen viestejä
 * Viesti abstrahoi ja kapseloi pyynnön
 * Viestin hyötykuorma voi olla iso tai pieni
 * Viestintä voi olla 
  * synkronista tai 
  * asynkronista
 * Viesti voidaan lähtettää tietylle kohteelle tai yleislähetyksenä kaikille tunnetuille/kiinnostuneille kohteille


###Viestinvälityksen peruskäsitteitä
* Point-to-Point vs. Publish-and-Subscribe
 * Queue vs. Topic
 * "Involved" vs Fire-and-Forget

####Point-to-Point
* Jono (queue) on erillinen nimetty resurssi, johon lähettäjä ja vastaanottaja muodostavat yhteyden (eivät siis suoraan toisiinsa)
 * Kummankaan ei tarvitse tuntea toista osapuolta (osoitetta tms.)
* Monta vaihtoehtoista vastaanottajaa
* Request-Reply -> tavitaan __kaksi jonoa__ ("Involved" relationship)
 * Pyyntöön liitetään tunniste, jolla vastaus palautetaan oikealle lähtettäjälle
* Publish-and-Subscribe
 * "Publisher" luo "Topicin", kaikki Topicin Consumerit saavat kopion viestistä

###Viestinvälitysarkkitehtuurit
* Tyypillinen tilanne (roolit)
 * Julkaisija-Tilaaja
 * Touttaja-Kuluttaja
* Verkkoratkaisussa tarvitaan kommunikointiprotokolla ja vqlittäjä (broker, JMS 2. Providder) huolehtimaan viestinvälityksestä
* Välittäjä (broker) tietää vastaanottajat (rekisteröityminen tai konfigurointi)
 * Julkaisija toimittaa viestin välittäjälle
 * Välittäjä toimittaa viestin edelleen siitä kiinnostuinelle tilaajille
####Välittäjä
* Vqlittäjään ja asynkroniseen viestintään perustuvaa mallia voidaan käyttää viestinnän runkona
* Arkkitehtuurissa määriteltävä seuraavat asiat:
 * Keskenään kommunikoivat komponentit
 * Viestit joiden avulla kommunikointi tapahtuu ilman että lähtettäjä tuntee vastaanottajan fyysistä sijaintia
 * Operaatiot joilla komponentit reagoivat viesteihin 
 * Säännót joiden avulla komponentit ja viestit rekisteröidään järjestelmälle
 * Palvelutasolupaus
* Säännöt joiden perusteella välittäjä tietää mille komponentille viesti on lähetettävä
 * Viestin vastaanottajan selvittäminen:
  * yleisviesti
   * etu: helpompi lähettää
* Rinnakkaisuus
 * Viestnvälittäjillä ja vastaanottajilla viestijonot
 * Voiko viestijono olla jaettu eri vastaanottajien kesken
 * Puskurointi, palvelutasot

####Tapahtumapohjaiset Viestinvälitysarkkitehtuurit
* Tapahtumapohjaiset arkkitehtuurit (event-driven)
* Komponentit kommunikoivat aiheuttamalla tapahtumia (event)
* Tapahtumat voivat välittyä kaikille muille komponenteille joista jotkut käsittelevät tapahtuman
* Tapahtuma
 * Tilanne joka voi sattua ohjelman suorituksen aikana
 * Edellyttää reagointia joiltain järjestelmän osilta
 * Tapahtumaan liittyy usein pieni määrä dataa
 * Lähde = tapahtuman synnyttävä komponentti
 * Tarkkailija = tapahtumaan reagoiva komponentti
* Lähde lähtettää tapahtumailmoituksen sitä tarkkailemaan rekisteröityneelle tarkkailijalle
 * Esim. Signals & Slots Qt-sovelluskehyksen olioarkkitehtuurissa
* Lähde tietää dynaamisesti tarkkailijoidensa olemassaolon mutta ei niiden tarkkaa tyyppiä
* Ilmoituksen lähetys voidaan hoitaa proseduurikutsuna tai sanomanvälityksenä (event bus, message bus)
 * proseduurikutsu synkroninen
 * Sanomajono asynkroninen/synkroninen

###Viestinvälitysarkkitehtuurit
* Etuja
 * Joustavuus, muunneltavuus, modulaarisuus
  * Uusien tuottajien/julkaisijoiden ja kuluttajien/tilaajien dynaaminen lisääminen
  * Välittäjän/väylän tekemät automaattiset esitystapamuunnokset, erilaisia palvelutasoja toteutettavissa
  * Komponenttien omatahtinen evoluutio
 * Paljon käytettyjen välittäjä-/väyläratkaisujen hyväksi kehittynyt laatu
  * Luotettavuus, skaalautuvuus, suorituskykyoptimoinnit
* Haittoja
 * Välittäjän tai tapahtumaväylän tuoma suoritusrasite (overhead) ja suorituskyvyn optimointimahdollisuuksien kaventuminen verrattuna suoriin (IPC-) yhteyksiin
 * Välittäjä tai väylä on kriittinen komponentti (single point of failure), jonka luotettavuus pitää saada paljon korkeammaksi kuin kommunikoivien komponenttien

##Muita hajautettuja arkkitehtuureja

###Vertaisverkkoarkkitehtuuri
* Symmetrinen ja ei-hierarkinen
* peer-to-peer
* Verkko jonka solmut voivat toimia sekä asiakkaina että palvelimina
* Uusi solmu kytkeytyy verkkoon liittymällä suoraan johonkin tuntemaansa verkon solmuuun
 * Solmut voivat dynaamisesti liittyä ja poistua
* Palvelupyyntö etenee verkossa solmusta solmuun kunnes löytyy solmu joka kykenee täyttämään pyynnön
 * Pyytäjä ja pyynnön täyttäjän välille voidaan muodostaa suora yhteys - tai sitten ei
* Rakenteettomassa verkossa pyynnön eteneminen sokeaa
 * Solmut tuntevat suorat naapurinsa mutta eivät näiden tarjoamia palveluita
* Rakenteellisessa solmut jakavat rakennetietoa palveluista ja tätä käytetään ohjaamaan etenemistä
* Edellyttää verkkoprotokollaa

* Etuja
 * Saatavuus paranee, jos palvelu/resurssi on hajautettu useina (osa-)kopioina verkon solmuihin, (esim. jonkin mediatiedoston fragmentit)
 * Vikasietoisuus kasvaa, koska yksittäisen solmun vikaantuminen ei ole kriittistä (tiedon/palvelun toisteisuus, vaihtoehtoiset saantipolut)
 * Skaalautuvuus ja laajennettavuus ovat hyvät, ei yksittäistä kriittistä pistettä
* Haittoja
 * Verkkoon voi muodustua saaria tai klikkejä, jonka solmut eivät ole yhteydessä klikin ulkopuolisiin solmuihin
 * Yksittäiset haut saattavat aiheuttaa paljon turhaa liikennettä (resurssia etsitään turhaan tai se löytyy monista solmuista)
 * Verkon rakenne ei vakaa (solmuja tulee ja lähtee)`

* Vertaissolmujen rinnalle onkin usein pakko luoda pysyviä super/ultra-solmuja jotka
 * liittävät uusia solmuja verkkoon
 * kytkeytyvät suoraan moniin alempiin solmuihin ja toisiinsa hakujen optimoimiseksi
 * Katso esim. Gnutella, Skype

###Map-Reduce -arkkitehtuuri
* Motivaatio
 * Hyvin suuren datamäärän hajautettu tallennus ja prosessointi
 * Data ja käsittelyoperaatiot suhteellisen yksinkertaisia, mutta niitä todella paljon
* Perusperiaate
 * Koko datamassa jaetaan pienempiin samankaltaisiin osiin
 * Osat käsitellään rinnakkain suoritettavissa tehtävissä jotka tuottavat paikallisen välityulksen

* Etuja
 * Skaalautuvuus, saatavuus, suorituskyky, varmistukset
  * rinnakkaisen käsittelyn massiivinen hyödyntäminen
* HUomattavaa
 * Suoritusnopeus riippuu siitq miten split-operaaatio onnistuu jakamaan syötedatan "yhtä vaativiin" ja keskenään samantyyppisiin rinnakkain käsiteltäviin palasiin
 * Reduce-operaatioita voidaan ketjuttaa mutta monimutkaisten operaatioiden koordinointi voi osoittautua hankalaksi

###Cloud


