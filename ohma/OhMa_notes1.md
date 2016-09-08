2016-09-06 OhMa luento 1
========================

Aloitusasiaa
------------

Pisteytys:
max | koe | laskarit 
--- | --- | --- 
36  | 30  | 6

Arvosana:
5 | 4 | 3 | 2  | 1  
--- | --- | --- | --- | --- 
30 | 27 | 24 | 21 | 18 

###Kurssikirja
Fairbanks G: Just Enough Software Architechture - A Risk-Driven Approach
E-versio:
http://rhinoresearch.com/book
 
###Harjoitustyö
* Erillinen kurssi
* Voi aloittaa milloin vain periodin aikana
* Yksilötyö
* Lopputulos 10-15 sivun raportti
* **Sisältö ja koko muuttuvat 2017 syksyllä**
* Tulee olemaan labramaisempi
* Nykyisen harjoitustyön voi tehdä 2018 vielä kevätlukukauden loppuun saakka

##Vierailuluento
* Olli Tietäväinen: Vaadin Framework 18.10

Luento
------

###Oppimistavoitteet
* Mitä on ohjelmistoarkkitehtuuri
* Miten aihetta kurssilla käsitellään

###Historiaa

Sovellusten määrä kasvanut exponentiaalisesti 1970-luvusta

Sovellusten toimintojen määrä kasvoi 1980-lukuun asti, siitä lähtien ollut laskussa

###Ohjelmistojen merkitys

2010-luvulla paljon käyttäjämäärältään globaaleja tietojärjestelmiä

Laskentateho, tiedonsiirto, hajautettu tallennus ja rinnakkainen käsittelu kehittyneet huimasti

Virtualistointi ja pilvestä saatava laskenta ja tallennuskapasiteetti antaa mahdollisuuden tarjota sovelluksia isoina `ohjelmistoratkaisuina`

Laadultaan hyvien ohjelmistojen totetus on entistä tärkeämpää (tehokkuus, tarkoituksenmukaisuus, luotettavuus, saatavuus yms.)

**Ohjelmistoarkkitehtuuri** tarjoa ratkaisun halutun laadun ja tuottavuuden saavuttamiseen

###Ohjelmistotekniikan kehityksestä

1970-80-luvuilla mietinnässä koodin uusiokäyttö, modulaarisuus, oliot jne.

###Ohjelmistoarkkitehtuuri

Rakenteet vs Suunnitelupäätökset

| Rakenteet           | Suunnittelupäätökset |
| --- | --- |
| Kattavuus           | Ominaisuudet         |
| Dokumentaatio       | Ymmärrys             |
| Suunnitelmallisuus  | Inkrementaalisuus    |
| Hallinta            |                      |

###Rakenteet

* Joukko rakentetia
* Kokoelma elemeenttejä ja niiden välisiä suhteita
* Ohjelmistoja monenlaisia ja monenkokoisia

####Tyypillisiä elementtejä ja rakenteita
* Kolme ollomuotoa
 * Staattinen, dynaaminen, operatiivinen
* Staattinen 
 * ohjelmiston koodi tiedostoissa (moduulit)
* Dynaaminen
 * Suoritusajan aktiiviset ja passiiviset oliot, prosessit, säikeet, data-entiteetit sekä kommunikaatiorajapinnat
 * Olioiden väliset data- ja kontrollivuot
 * Usean olion muodostamat, roolinsa ja toimintansa perusteella selkeästi erottuvat kokonaisuudet
 * **Huom: ei yksi yhteen vastaavuutta staattisten rakenteiden kanssa**
* Operatiivinen (sijoittelu, allokaatio)
 * Dynaamisten oloitden ja palveluiden sijoittelu ja suoritus laitteistossa
 * Ohjelmiston paketointi konfigurointi ja piirteiden valinta tiettyä käyttökontekstia varten

####Abstraktit rakennekuvaukset
* Rakenteen dokumentoitu kuvaus usein abstrakti
 * Epäoleelliset ykstiyiskohdat pois
 * Suunnitelmassa eivät toteutuksen yksityiskohdat ole tärkeitä
 * Tarkastelu yleensä järjestelmätasolla, jossa rakenneosat suuria
 * Näkymät muodostavat hierarkian, alempi taso tarkentaa ylemmän tason osan

####Rakenteet ja ohjelmiston ominaisuudet
* Rakenteiden perusteella voidaan tehdä päätelmiä ohjelmiston luotettavuudesta, tarkoituksenmukaisuudesta, tehokkuudesta yms. ns. sidosryhmille tärkeistä ominaisuuksista
* Halutut ominaisuudet vaikuttavat siis siihen mitä rakenteita arkkitehtuurissa tarkastellaan
 * Ja kunika tarkkoja tai yksityiskohtaisia kuvauksia tarvitaan
* Arkkitehtuuri ei ole itsetarkoitus vaan väline

###Suunnittelupäätökset

Ohjelmistoarkkitehtuuri on joukko tehtyjä suunnittelupäätöksiä

####Arkkitehtuuritason suunnitelupäätös
* Kaikki arkkitehtuuri on suunnitelua mutta kaikki suunnitelu ei arkkitehtuuria
* Tunnusmerkkejä
 * Koskee järjestelmätason asioita ja vaikuttaa muiden vaatimusten kuin järjestelmän tarjoamia palveluja tai toimintoja koskevien vaatimusten toteutumiseen
 * Ohjaa ja/tai rajoittaa muita suunnnittelupäätöksiä

####Arkkitehtuuri
* Suunnittelupäätökset määrittävät sovelluksen arkkitehtuurin
* Ohjelmistoarkkitehtuuriin kuuluvat ne ohjelmiston suunnittelupäätökset jotka merkittävästi vaikuttavat ohjelmiston laadullisten ominaisuuksiksen saavutamiseen
* Tyypillisiä arkkitehtuuripäätöksiä
 * Komponentteihin jako
 * Tiedon tallennus- ja saantiratkaisut
 * rajapintojen tunnistaminen ja erottaminen
 * Suorituskykyyn yms. vaikuttavat ratkaisut
 * Järjestlemän ylläpitöä tukevat ratkaisut

####Arkkitehtuuri ja muu suunnittelu
* Suunnittelu - päätetään minkälaisista elementeistä ihjelmiston toteutus koostuu (luokat, oliot, rajapinnat yms)
* Miten vedetään raja arkkitehtuurin ja muun suunnitelun välille
* Arkkitehtuuriset suunnitelupäätökset vaikuttavat ohjelmiston muihin suunnitelupäätöksiin
* Raja häilyvä
* Laatuominaisuuksiin vaikuttavat suunnittelupäätökset hyvin tunnistettavissa

###Määritelmien yhteensovittaminen

Molemmat ovat järkeviä näkökulmia ja täydentävät toisiaan

Rakenteita tarvitaan ohjelmiston monimutkaisuuden yleiseen hallintaan, suunnittelupäätöksia tarvitaan ratkaisujen syvälliseen ymmärärtämiseen ja arviointiin
* Dokumentaatio- ja kontrollikeskeiset prosessit pitäväþ rakenteiden kattavaa määrittelyä tärkeänä
* Suunnitelupäätöksiin keskittyvä arkkitehtuurityö tyypillistä ketterille kehitysmenetelmille 
