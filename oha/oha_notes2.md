2016-09-08 Oha luento 2
=======================

Päivän aiheet:
* arkkitehtuurin hyödyt ja käyttö
* kuinka paljon arkkitehtuuria
* miten arkkitehtuuri nivoutuu muuhun kehitystyöhön

Arkkitehtuurin ilmeneminen
--------------------------
* ohjelmistoelementtien välisten suhteiden muodostamat rakenteet tai joukko suunnittelupäätöksiä
* konkreettisesti rakenteet / päätökset:
  * ideoina ja periaatteina (kehittäjien mielessä)
  * konkrettisiina rajoittena (suunnittelulle ja toteutukselle)
  * dokumentteina (muodollinen tai vaaamuotoinen)
  * malleina (UML, formaalit mallinnuskielet)
  * koodina (kirjastot, kehykset, alustat, riippuvuudet, nimentä yms.)
    * koodi on lopullenen toteutus, ei vastaa aina suunnitelmia

Arkkitehtuurin käyttötavat
--------------------------

###Ohjaava käyttö

* Arkkitehtuuri määrittä järjestelmän perusrakenteen
  * Analogiana eläimen luuranko
  * Akkritehtuurin lähtökohdaksi voidaan valita tyyli tai patterni, joka kiinnittää elemnttien tyypit/vastuut/roolit ja niiden välisten liitosten ja yhteyksien ominaisuudet
  * Ei voida sanoa onko jokin tyyli aina parempi kuin toinen, riippuu kontekstista
* Arkkitehtuuri vaikuttaa laatuominaisuuksiin
  * Arkkitehtuuri mahdollistaa haluttujen ominaisuuksien saavuttamisen
  * Sopimaton arkkitehtuuri voi myös estää sen
* Arkkitehtuuri on (enimmäkseen) riippumaton toiminnallisuudesta
  * Sama toiminnallisuus, monta arkkitehtuuria
  * Huonosti valittu arkkitehtuuri voi haitata toiminnallisuuden toteutusta
* Arkkitehtuuri ohjaa toteutusta rajoitteilla (guide rails)
  * Esimerkiksi halutaan suoraan kieltää käytettävyyden tai tietoturvallisuuden vuoksi huonoiksi tiedetyt ratkaisut
  * Annetaam malli, jonka mukaan tietyt asias toteutetaan (laatuvipu)
  * Rajoitteet auttavat kehittäjiä monin tavoin (kokemuksen siirto, käsitteellinen eheys, ajonaikaisen käyttäytymisen helpompi ymmärrys)

###Kuvaileva käyttö

* Ohjelmiston ja suunnitteluratkaisujen ymmärtäminen
  * Abstrahointi yksityiskohtia pois suodattamalla
  * Sopivasti valitut rakenteet ja niitä tietystä näkökulmasta esittävät näkymät (view) ovat erinomaisia ymmärryksen lähteitä
  * Uudet kehittäjät, johto, asiakkaat, alihankkijat jne.
* Liiketoiminnallisten tavoitteiden toteutumisen seurraaminen
  * tuoteperheet, cots-komponenttien käyttö, integrointi ulkoisiin palveluihin, standardointi, lisenssointi jne.
* Rajoitteiden noudattamisen valvonta
* Organisaation kehittäminen
  * Vahvasti toisiinsa kytkeytyvien elementtien kehittämisvastuun jako kannatta miettiä tarkkaan kommunikaatio-ongelman välttämiseksi
    * Convwayn laki - organisaatio ja arkkitehtuuri muistattavat ennen pitkää toisiaan
* Riskien hallinta
  * Arkkitehtuurityö kannattaa keskittää tunnistettujen riskien elminointiin tai lieventämiseen
* Vaatimusten täsmentäminen
  * Vaadittujen laatuominaisuuksien analysointi ja arkkitehtuurin suunnittelu niiden saavuttamiseksi auttaa huomaamaan ristiriitaisuuksia ja epätäsmällisyyksiä vaatimuksissa ja määrittelyissä
  * Arkkitehtuurin suunnitteluun liittyvä laatuominaisuuksien tasapainottelu pakottaa priorisoimaan laatuvaatimukset

Kuinka paljon arkkitehtuuria
----------------------------

Kaikilla ohjelmistoilla arkkitehtuuri

###Tapa 1: Arkkitehtuuri yhdentekevää

* Monissa projekteissa ei arkkitehtuurityötä
* Syitä 
 * Tietämättömyys - mennään tuurilla
 * Pieni projekti/pienet riskit - mikä vaan tod. näk toimii
 * Oletusarkkitehtuurin käyttö

Oletusarkkitehtuuri

* Vakiintuneet teknologiat / toimittajat jotka muodostuneet standardeiksi
 * Nobody ever got fired for buying IBM
* Tarjolla ohjelmistokehyksia ja alustoja jotka
 * tarjoaa perustoiminnalisuuden
 * Kiinnittää laatuominaisuudet
  * turvallisuus, suorituskyky, ylläpidettävyys...
 * Vapauttaa sovelluskehittäjän keskittymään sovelluskohtaisen toiminnallisuuden toteutukseen
* Ei suoranaisesti huono ratkaisu
* Riskejä
  * arkkitehtuurin rapautuminen suunnitteluun puutteesta
  * monimutkaisuus joka kehysten ja alustojen piirteiden myötä tulee ratkaisuun mukaan
* Referenssiarkkitehtuuri
 * Esimerkinomainen ratkaisu järjestelmän arkkitehtuurille
 * Laatija halaa uudeksi oletusarkkitehtuuriksi

###Tapa 2: Arkkitehtuurikeskeinen

* Tunnusmerkkeinä ovat
 * tietoinen arkkitehtuurin valinta ja suunnittelu
 * laatuvaatimusten ymmärtämisen pohjalta

###Tapa 3: Arkkitehtyyru laatuvipuna (hoisting)

* Arkkitehtuuriratkaisu implementoidaan koodiksi ja tuodaan suoraan kehittäjien käyttöön
 * Koodikirjasto, komponentti, tai konkreettinen valvottu rajoite
 * frameowrkit
* Valmiin koodin käyttö takaa halutut ominaisuudet ilman kehittäjän vaivaa
* Suhteellinen pieni määrä työtä (uudelleenkäytettävä koodi) -> iso vaikutus

Laatuvipu
* Vivun käyttöön liittyy usein harkintaa laatuominaisuksien tasapainottelun kannalta (trade offs)
 * Vipua voi olla pakko käyttää, joten vivutetun ominaisuuden syytä olla tärkeä
* Vivutus vai hivutus?
 * Rajoitukset voivat haittata kehittäjiä, kuitenkin:
 * Vapauttaa aikaa muihin asioihin
 * Kaikki eivät experttejä hankalissa asioissa -> anna expertin tehdä kertaalleen

###Millaisissa projekteissa arkkitehtuurityö on erityisen tärkeää

* Pieni ratkaisuavaruus 
 * Toimivia ratkaisuja on vähän ja löytäminen vaikeaa
 * Todl. näk että mikä vain arkkitehtuuri toimii siis pieni
* Ohjelmistohäiriöiden vakavat seuraukset
 * Vahingot ihmisille, ympäristölle ja omaisuudelle
* Vaikeat laatuvaatimukset
 * Saakalautuvuus, ylivertainen käyttökokemus
* Uusi sovellusalue
 * Uudet käsitteet, toiminnot, vaatimukset, teknologiat jne
 * Ei tuttua kaavaa tai rakennetta
* Tuoteperheet
 * Yhteinen tuoteperhe
 * Ei toistuvaa toiminnallisuutta moneen kertaan

Ajatuskoe, mitä seurauksia väärillä arkkitehtuuriratkaisuilla:
* Jos ei mikään, arkkitehtuuri on w/e

##Ohjelmistoarkkitehtin tiedot ja taidot

###Mitä arkkitehdit tekevät?

####Ratkaisuarkkitehti
* Toimii asiakasrajapinnassa
* Tulkitsee asiakasvaatimukset, muodostaa ratkaisusuunnitelman
* Osallistuu työmäärien ja kustannusten arviointiin
* Tavoitteena globaalien resussien ja aikaisempien ratkaisujen sekä organisaation osaamisen kustannustehokas käyttö

####Tekninen arkkitehti
* Tietyn teknologia-alueen kehityssuunta ja arkkitehtuuri
* Teknisten vaatimusten ja ohjelmistosuunnitelmian teko liiketoiminta- ja asiakasvaatimusten perusteella
* Kehittää arkkitehtuurikomponentteja
* Osallistuu yksityiskohtien suunnitteluun ja koodikatselmointeihin
* Analysoi suorituskyky- ja tehokkuusongelmia
* Osallistuu käytännón toteutukseen ohjaajana ja itse implentoimalla

##Prosessiajattelu

**Kaksi ääripäätä**

BDUF | emergence
--- | ----
suunnitelmat | muutos
kontrollointi | reagointi
riskien hallinta | mukautuminen
 | refaktorointi

*BDUF = Big Design Up Front


