Ohjelmistoarkkitehtuurit Luento 6
=================================

##Viime luennosta eteenpäin

###Kerrosarkkitehtuurit
* Layered architechtures
* Koostuu tasoista jotka järjestetty jonkin abstrahointiperiaatteen mukaan nousevaan järjestykseen
 * Usein abstrahointi akselilla: ihminen-laite
  * Sovellus - Palvelu - Resurssi
 * Usein kerrokset luonteeltaan niin teknisiä että eri abstraktiotasojen nimeäminen ja erottaminen käsitteellisesti toisistaan on hankalaa
  * Alemman tason palvelut tyypillisesti primitiivisempiä ja yleiskäyttöisempiä kuin ylemmän tason palvelut jotka ovat erikoistuneempia (tietty, rajatumpi tarkoitus)
* Kerrokset ovat yleensä nähtävissä yhden suoritusympäristön (tietokoneen, solmun) sisällä suoritetttavan ohjelmiston rakennetta ja sen käyttämiä palveluja tarkasteltaessa
 * Eri kerrokset eivät yleensä ole hajautettuja eri solmuihin suoritusympäristössä toisin kuin kolmitasooarkkitehtuurissa
 * Kerroksisuus ohjelmiston sisäinen periaate

* Virtuaalikoneet (virtual machines) kerrosarkkitehtuurityyppinä
 * Perusajatus:
  * Taso toimii virtuaalikonena, joka tarjoaa palveluita ylemmän tason korkeamman abstraktion virtuaalikoneelle. Ylemmän tason tarjoamat palvelut toteutetaan välittömästi alemman tason palveluita hyväksikäyttäen.
  * Toteutuu vain puhtaassa kerrosarkkitehtuurissa

* Käytännössä puhtaasta kerrosarkkitehtuurista voi olla kahdenlaisia poikkeamia:
 * Palvelukutsuja tehdään alemmasta kerroksesta ylempään kerrokseen
 * Palvelukutsu ohittaa kerroksia kulkiessaan ylhäältä alaspäin (avoin kerrosarkkitehtuuri)
* Kerrosten ohitus on usein tarpeen suorituskykysyistä (tai välissä oleva kerros ei toteuta tiettyä palvelua joka löytyy alemmalta)

* Kerroksen ohittamisesta aiheutuva ongelma:
 * Tietty kerros tulee riippuvaiseksi myös muista  kuin suoraan sen alapuolella olevasta kerroksesta
  * Kerroksen vaihtaminen hankalaa
* Palvelukutsun tekeminen alemmasta kerroksesta ylempään päin voi olla merkki vakvasta ongelmasta arkkitehtuurissa
 * Alempi kerros riippuvainen ylemmästä?
 * Syklinen riippuvuus?

* Joskus alemman kerroksen tarpeen kutsua ylemmän kerroksen koodia
 * Alemman kerroksen täytyy mukauttaa toimintaansa ylemmän kerroksen mukaan
 * Jotta alempi kerros ei tulisi (liian) riippuvaiseksi ylemmästä kerroksesta voidaan hyödyntää takaisinkutsuperiaatetta (callback)
  * Alempi kerros tarjoaa rekisteröintioperaation jonka avulla ylempi kerros rekisteröi takaisinkutsuusa kutsuttavan koodin alemman kerroksen käyttöön
  * Alempaa kerrosta ei kiinnosta mitä ylemmän kerroksen takaisinkutsufuktio tekee, se vain kutsuu sitä tietyssä tilanteessa

* Kerrosten väliset selkeät rajapinnat -> kerros voidaan vaihtaa toiseksi vaikuttamatta muuhun järjestelmään
* Rajapintojen toteuttaminen lisää kerrosten vaihdettavuutta

* Esimerkkejä:
 * OSI-järjestelmä
 * Virtuaalikone, esim. Java,
 * Sovellusrajapinnat palveluihin (API)
  * Käyttöjärjestelmien, luokkakirjastojen
   * Kätkee yksityiskohdat, tarjoaa toiminnallisuuden

* Etuja
 * Yleinen malli, kaikenkokoisiin
 * Helposti ymmärrettävä
 * Ohjaa ohjelmiston riippuvuuksien minimointiin
 * Tukee uudelleenkäyttöä
* Ongelmia
 * Tehokkkuushäviö:
  * Palvelukutsu ei välity suoraan palvelun toteuttavalle kerrokselle
  * Parametrit mahdollisesti muutettava eri esitysmuotoon
 * Toteutustaakka: jokainen palvelu toteutte joka tasolla (vaikka varsinainen toteutus vain sen toteuttavalla tasolla)
 * Oikean tasojaon keksiminen on hankalaa
  * Mihin kerrokseen tietty palvelu pitäisi liittää?
 * **Poikkeusten käsittely**
 * Kutsu ylemmältä kerrokselta -> poikkeus kerrosrakenteen pohjalla -> palataan kutsupinossa taaksepäin kunnes löytyy käsittelijä poikkeukselle -> poikkeuksen käsittely ylemmällä tasola kuin missä poikkeus tapahtui -> käsittelijä ei pysty korjaamaan tilannetta
 * Miksei poikkeuksia käsitellä omalla tasollaan?


##Varsinainen luennon asia

###Laatutekijät arkkitehtuurisuunnittelussa
* Onnistunut arkkitehtuuri edellytys järjestelmän keskeisten laatuvaatimusten täyttymiseksi
* Yksittäinen arkkitehtuurityyli tai patterni ei kuitenkaan ota kantaa kaikkiin mahdollisiin laatuvaatimuksiin. 

* Laatuominaisuudet vaiikuttavat toisiinsa
 * Monilla laatuominaisuuksilla negatiivinen vaiktus suorituskykyyn

* Ohjelmistojen laatumalli: ISO 25000 standardisarja aka SQuaRE luettavissa Kumpulan tiedekirjastossa

* Bass et al. ovat määritelleet taktiikoita laatuominaisuuksien saavuttamiseen
 * Taktiikka on __suunnitteluprimitiivi__ joka vaikuttaa __tietyn laatuominaisuuden__ toteutumiseen
 * Tyylejä ja malleja yksityiskohtaisempia ja lähempänä toteutusta ja yleiskäyttöisiä
  * Voidaan soveltaa monessa eri kontekstissa

####Suorituskyky

* Vasteaika ja suoritusteho riippuvat:
 1. resurssien käytöstä
 2. odotusajasta
  * kilpailu resursseista
  * resurssin saatavuus
  * riippuvuus muusta toiminnasta
* Suorituskykytaktiikat:
* Resurssitarpeeseen vaikuttavat taktiikat (= kuinka plajon prosesointia saapuvan työn tekeminen vaatii)
 * laskennan tehostaminen (algoritmi, välitulosten käsittely)
 * yleisrasitteen vähentäminen
 * tapahtumamäärän vähentäminen
 * tapahtumien vastaanoton kontrollointi
 * käsittelyajan rajoittaminen
 * jonojen koon rajoittaminen
 * Huom: laskennan määrää vähennettäessä joudutaan usein tinkimään tulosten tarkkuudesta
* Resurssien hallintataktiikat (= kuinka paljon ja millaisia resursseja käytetään)
 * rinnakkaisuuden lisääminen
 * toiminnan / datan monistaminen
 * resurssien / tehokkaampien resurssien lisääminen
* Resurssien allkointitaktiikat (= miten eri työt saavat resursseja käyttöön)
 * jono
 * prioriteettijono
 * dynaaminen prioriteettijono
 * staattinen allokointi

####Muunneltavuus

* Muunneltavuustaktiikat (modifiability tactics)
 * Ohjelmiston muunneltavuutta mitataan laskemalla kustannuksia jotka kuluvat ohjelmistomutosten toteuttamiseen testaamiseen ja käyttöönottoon
 * Muunneltavuutta lähellä olevia tekijöitä: adaptability, evolvability, maintainability

#####Muunnosten lokalisointi
* Tavoitteena rajoittaa odotettavissa olevien muutosten vaikutus mahdollisimman pienen joukkoon komponentteja
 * Määrätään komponenttien vastuut siten että odotettavissa olevat muutokset koskevat rajattua joukkoa komponentteja

#####Heijastusvaikutusten esto
* Ohjelmamuutoksen heijastusvaikutukset (ripple effects) tarkoittavat muutoksia jotka täytyy tehdä moduuleihin joita varsinainen muutos ei suoraan koske
* JOs moduulia A muutetaan niin moduulia B joudutaan muuttamaan vain siksi että A:ta on muutettu - ei siksi että B:n ominaisuuksia on ollut tarve muuttaa
 * Tämä heijastusvaikutus johtuu siitä, että B:n toteutuksessa on jokin riippuvuus A:n toteutukseen

#####Sidonnan viivävästäminen
* Edellä kuvatut taktiikat pyrkivät vähentämään muutosten kustannuksia pienentämällä muutettavien moduulien määrää
* Niistä ei kuitenkaan hyötyä jos halutaan lisätä ohjelmiston muunneltavuutta koskien moduulien käyttöönottotapaa

###Testattavuus

####Testattavuustaktiikat
* Ohjelman tai sen osan testauksen malli:
 * Ohjelma (testauksen kohde)
 * Annettu syöte
 * __Oraakkeli__ tarkistaa tuottaako ohjelma tietyllä syötteellä oikean tuloksen -> hyväksytty/hylätty

* Jotta ohjelmistoa (tai sen osaa) voi mielekkäästi testata:
 * Kontrolloida ohjelman ja sen osien syötteitä
 * Havaita sen tuottamat tulokset
 * Ja joissain tilanteissa myös voitava tarkkailla ohjelman sisäistä tilaa syötteen käsittelyn aikana tai välittömästi käsittelyn jälkeen
* Tähän tarvitaan yleensä testipeti (test harness)
 * testien laatimisen ja suorittamisen sekä testipetien rakentamisen kustannukset voivat olla huomattavat
 * Testien suorituksen ja tulosten raportoinnin automatisointi avain olennaista ketterässä kehityksessä`
* Syötteiden ja tulosteiden kontrollointi
 * Record/Playback
 * Stub/mocking
 * Erikoisrajapinnat testikohteille
* Sisäisen tilan monitorointi
 * Kohde ylläpitää tietoa omasta tilastaan, kuormituksestaan yms. ajon aikana
 * Monitorinti pysyvää tai tiläpäistä
 * erityiset set/get/reset-operaatiot
