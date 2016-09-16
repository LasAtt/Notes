2016-09-15 luento 4 
===================

##Jatkoa luentoon 3

###"Kaunis arkkitehtuuri"
* One fact in one place, yksi toiminnallisuus toteutetaan kerran
* Automatic propagation
 * Lokalisoidun "faktan" kopiointu suoritusaikana käyttökontekstiinsta on joskus tarpeen (saman komponentin instantiointi ja konfigurointi eri palveluissa
 * Automaattinen ja työkalun tukema (esim. dependency injection)
* Architechture includes construction
 * Ohjelmiston koostaminen ja rakentaminen (build) huomioon arkkitehtuurissa
 * Esim. reflektion on hyvä mekanismi jota kannattaa hyödyntää paitsi suoritusaikana myös suoritettavaa ohjelmaa koostettaessa. (esim. convention over configuration -periaate)
* Minimize mechanisms
 * Periaatteessa saman asian tekevien hieman erilaisten mekanismien määrä karsittava minimiin
 * Riittävä hyvä ratkaisu kertaalleen toteuttena on parempi kuin kymmenen erillistä joka tilanteeseen "parasta" ratkaisua (vrt. conceptual integrity)
* Construct engines
 * Ajatellaan palveluita moottoreina, virtuaalikoneina jotka tarjoavat geneerisen rajapinnan palveluihinsa
 * Primitiivisiä ja yleiskäyttöisiä
 * Yleistä kerrosarkkitehtuurissa
* O(G), the order of growth
 * Ota huomioon järjestelmän tod.näk kasvu
 * Pienen järjestelmän ratkaisu ei ehkä toimi isommasssa
* Resist entropy
 * Pyri pitämään arkkitehtuuri eheänä
 * Ajan myötä käytetys arkkitehtuuriratkaisut himmenevät -> resist this
 * Työkaluilla tärkeä rooli

**Beatiful architechtures do more with less**

##Arkkitehtuurityylit ja patternit

###Oppimistavoitteet
* Yleisimmät patternit ja tyylit
* Käydään muutama läpi perusteellisemmin, N-Tier, MVC, Web-MVC, tietovarasto

###Tyylien ja patternien käytöstä
* Platoninen ja "ruumiillistunut" tyyli/patterni
 * Platoninen on ideaalikuvaus
 * Käytännóssä harvoin puhtaita, kaikilta yksityiskohdiltaan ei vastaa tyyliä/patternia
 * Tyylit ja patternit yleistyksiä
  * Yleistys määrittää arkkitehtuurin luokan
* On myös sovellusalue- ja teknologiakohtaisia patterneja joilla rajatumpi sovellusala

###Ajatuskoe
* Konkreettinen sovellusesimerkki voi auttaa ymmärtämän tyylejä ja niiden käyttöä
* Ajatellaan web-kauppaa jossa myydään jotain fyysisiä tuotteita (esim. vaatteita ym.
 * Mitä kaikkia toimintoja web-kaupan tietojenkäsittelyjärjestelmän pitää toteuttaa? Mitä kaikkea sen pitää tehdä?
 * Mitä laatuvaatimuksia toimintoon liittyy?
 * Mitä teknisiä asioita/ratkaisuja toteutukseen liittyy?

##Arkkitehtuuripatterneja

###Kolmitasoarkkitehtuuri (N-Tier)
Display (Presentation)  <-> 'Business' logic <-> Persistent state (Datastore)

Display
* Käyttäjän näkymä
* Datan katselu
* Datan muokkaus

'Business' logic
* Operaatiot joita käyttäjä haluaa järjestelmän tekevän datan perusteella
* Liiketoimintaprosessit- ja entiteetit

Persistent state
* Datan pysyvä tallennus ja jakaminen eri sovellusten kesken

Display ---service requests---> Business logic

Business logic ---values to display--> Display 

Business logic ---data requests---> Persistent state

Persistent state ---data values---> Business logic

###N-tier
* Käytännnössä isoissa järjestelmissä puhutaan kolmen tason sijaan usein monitasoisesta rakenteesta (N-Tier)
* BUsiness logic-taso jaetaan yleensä edelleen palvelupyyntöjen vastaanottoon ja käyttäjä-istuntojen hallinnan tasoon sekä palvelut toteuttavien operaatioiden ja "business-olioiden" tasoon
* Business-oliot taas käyttävät yritysjärjestelmätason palveluita (tietokannat, toiset järjestelmät)
* __N__ siis yleensä 4 tai jopa 5
* Sovellusalue
 * Hajautetut, data-intensiiviset informaatiojärjestelmät
* Edut
 * helpottaa tietoturvan suorituskyvyn ja saatavuuden optimointia eri tasoilla niille sopivilla tavoilla
 * Lisää järjestelmän modullarisuutta ja muunneltavuutta, koska eri tasojen välille täytyy sopia määrämuotoiset kommunikaatioprotokollat (-> loose coupling)
* Haitat
 * Kustannukset, monimutkaisuus

###Klassinen Model-View-Controller malli
* Sovellusalue: monimuotoisia käyttöliittymänäkymiä sisältävät interaktiiviset järjestelmäþ
* Motivaatio: 
 * Ohjelmistolla erilaisia käyttäjiä ja näillä erilaisia tarpeita käyttöliittymään liittyen
 * Samaa informaatiota pitää pystyq esittämään ja käsittelemäqn eri muodoissa
 * Käyttöliittymän tulisi olla helposti muotoiltavissa

####Klassinen MVC
* Kolmenlaisia komponentteja
 * Malli-komponentit vastuussa laskeentaan liittyvän tiedon säilytyksestä
 * Näkymä-komponentit vastuussa tiedon esittämisestä käyttäjälle
 * Kontrollerit vastuussa tiedon interaktioiden logiikan hoitamisesta

* Mallikomponentit eivät riipu mistään "tietystä" näkymä- tai ohjainkomponentista
* Muutokset malikomponenteissa välitetään näkymille __Tarkkailija__-suunnittelumallin mukaisesti
 * Ei vain niille näkymille jotka ilmaisseet kiinnostuksensa muutoksiin

####MVC-arviointia
* Etuja
 * Useita näkymiä samaan 
 * Näkymiä helposti lisättävissä vaikka dynaamisesti
 * Ohjeimon voi helposti vaihtaa
 * Voi toimia perustana sovelluskehykselle (Smalltalk, Web-applikaatiot)
* Ongelmia
 * Lisää mutkikkuutta
 * Yksinkertainen käyttäjätoimenpide saattaa aiheuttaa monia päivityksiä näkymään
 * Voi olla työlästä löytää sopiva datan esitysmuota ja haku-/päivitysoperaatiot malllin rajanpintaan käyttóliittymän (näkymän) suorituskyvyn (responsiivisuus) kannalta

####Muunnelmia
* Monesti ei tarpeen erottaa ohjainta ja näkymää
 * Monissa käyttöliittymäkehyksissä "kontrollerikoodi" liitetään UI elementteihin suoraan tapahtumankäsittelijöinä
* Ts. komponentti voi toimia sekä näkymä- että ohjainkomponettina. Yhteen malliin voi liittyä monta <näkymä, ohjain>-paria

###Web-MVC
* MVC-patternin idea erottaa sovelluksen data ja tila näiden esittämisestä käyttäjälle on niin hyödyllinen että sitä sovelletaan laajasti web-sovellusten toteutuksessa
 * Myös eri konteksteissa
* Client-side MVC-: AngularJS
 * "Model-View-**Whatever**"

###MVC + N-Tier
* Toisensa poissulkevat vai yhteistyössä toimivat?
 * Harjoitustöissä

##Arkkitehtuurityylejä

###Tyylien luokittelua
* Eri lähteet luokittelevat tyylejä eri tavoin
 * Fairbanks ei lainkaan
* Tarkastellaan muutamaa esimerkkiä eri luokista
 * Jaettu tietovarasto
 * Tietovuopohjaiset tyylit

###Jaettuun tietovarastoon perustuva arkkitehtuuri
* Data ceneter - Shared state - Repository
* Joukko komponentteja ylläpitäq yhteistä tilaa tietovarastossa
 * Erilaisia muunnelmia sen mukaan kuinka aktiivinen rooli tietovarastolla
* Kahdenlaisia komponentteja
 * Keskitetty tietorakenne: tietovarasto
 * Asiakaskomponentit: hakevat tietoa ja muokkaavat sitä, eivät yhteydessä toisiinsa
* Järjestelmän kontrolli määräytyy tietovaraston tilan mukaan
* Vuorovaikutus käsittelijöiden välillä tapahtuu ainoastaan tietovaraston kautta
* Käsittelijöiden tietovarastoon tekemät muutokset johtavat viaheittan haluttuun lopputulokseen
* Käsittelijän aktivointi
 * Käsittelijät voivat pollata tietovarastoa tutkiakseen onko tila sellainen mistä käsittelijä pystyy jatkamaan toimintaa
  * jos on käsittelijä tuottaa tuloksia jotka kirjataan tietovarastoon
 * Tietovarasto voi aktivoida käsittelijän jonkin säännön tai triggerin perusteella
* Käsittelijät toimivat rinnakkain
 * Edellyttää samanaikaisuuden hallintaa: tiedon lukitus
* Esim. teköälysovellukset (blackboard-arkkitehtuuri), Wikit, Google docs, MS Sharepoint, muut verkkotyöalustat

####Edut ja haitat
* Etuja 
 * Muunneltavuus & Laajennettavuus
 * Rinnakkaisuuden hyödyntäminen

* Haitat
 * Rinnakkaisten ja päällekkäisten päivitysten hallinta

###Tietovuopohjaiset tyylit
* Data flow styles
* Pääpaino siinä miten tieto liikkuu toisistaan riippumattomien tietoa prosessoivien komponenttien välillä

**Erätöiden sarja (Batch sequential)**
 * Perinteinen eräajosovellus
 * Tiedon käsittely vaiheittainen
 * Lopputulos kun kaikki vaiheet suoritettu
 * Ei rinnakkaisuutta
 * Vuonohjaus (job control)
* Erätöiden sarja jatkuu:
 * Tieto liikkuu kokonaisuuksina vaiheesta vaiheeseen
 * Vaiheelle voi tulla useita syöttöaineistoja
 * Vaihe käsittelee syötteen kokonaisuudessaan ennen seuraavaan vaiheeseen siirtämistä
* Sovellusalueet
 * XML-käsittely
 * Monivaiheinen tiedonkäsittely

Etuja
* Muunneltavuus, vaiheet toisistaan riippumattomat
* Yksinkertainen rakenne
* Hyvä suorituskyky
Haittoja
* Tulos valmis ja saatavilla vasta kun viimeinen vaihe valmis (ei inkrementaalisuutta)
* Rinnakkaisuutta ei voi hyödyntää

**Väylät ja suodattimet**
* Koostuu prosessointiyksiköistä (filter) ja väylistä (pipe)
* Kukin suodatin oma entiteetti
 * Ei jaettua tilatietoa
 * Prosessointiin vaikuttaa ainoastaan syötet
* Huono interaktiivisiin sovelluksiin

**Liukuhihna**
* Looginen liukuhihna (pipeline)
* Lähdekoodi -> Selaaja -> Jäsentäjä -> Semanttinen analyysi -> Koodin generointi -> Tuloskoodi
