# ExtendedMacro
ExtendedMacro is plug-in for BurpSuite proxy. It provides similar but extended functionality of BurpSuite Macro feature. The main functionality is, that you are able to trigger one or more request before every request triggered from Intruder, Repeater, Scanner, Sequencer or Spider (except tools Proxy and Extender). You can extract data from arbitrary response of the request and replace or add data to the following request (replace CSRF token, session, add new header ...).

It is still in development, so please don't be angry if something getting wrong, rather let me know to fix it ;).

## Features
- create sequence of the request to be triggered before the every request call
- extract data from arbitrary response
- paste extracted data into arbitrary following request
  - from the sequence
  - into the last request (Intruder, Repeater, Scanner, Sequencer or Spider)
- create new header
- changing order of the requests

## Advantages against the BurpSuite Macro
- ability to replace arbitrary string in the request
- ability to add new header into the request
- easier configuration than macro (does not seems to be, but it is ;))

## About the UI
The plug-in adds new tab into the BurpSuite named "ExtendedMacro". It contains several tabs: "Main", "Logger" and "Settings".

### Main
In the main window you are able to configure all the magic. The left part of the view is the "Extraction message list" and the right part is the "Replace message list".

#### Extraction message list
Here you can set up what requests will be triggered and what data will be extracted from their responses. After selecting the message, you can set the extraction by the selection of the response.

#### Replace message list
Here you can set up what data from extraction will be added/replaced in the following requests. The replace string can be set by the selection of the request.

### Logger
Logs all messaged what were modified or triggered by ExtendedMacro.

### Settings
He you can specifies what tool will use the ExtendedMacro plug-in.

## How to
1. Select messages e,g, in the Proxy tab, do right mouse click and select "Send to ExtendedMacro"
2. go to ExtendedMacro and click on the message in the "Extraction message list"
3. select data from the response editor
4. click "From selection" button
5. set extraction name and click "Add" button
6. click on the message in the "Replace message list"
7. select data from the request editor and click "From selection" button
8. set replace name and type (replace on the selected message)
9. select the extraction
10. click replaces "Add" button
11. now you are done and your request will be triggered, you can see it in the "Logger" tab.

## Screen-shots

Main

![Main tab](/screenshot/main.png?raw=true "Main tab")

Logger

![Logger tab](/screenshot/logger.png?raw=true "Logger tab")

Settings

![Settings tab](/screenshot/settings.png?raw=true "Settings tab")

Video https://www.youtube.com/watch?v=IwKa0F7MmTM

[![ExtendedMacro usage](http://img.youtube.com/vi/IwKa0F7MmTM/0.jpg)](https://www.youtube.com/watch?v=IwKa0F7MmTM)

# Contribution
Feel free to create pull request or issues.

# Donation
Thank you very much and enjoy :).

| PayPal | Bitcoin |
| ------ | ------- |
| [![](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=P6JB98K7TNJNG&lc=SK&item_number=ExtendedMacro&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted) |  <center> ![19YoCcuruuovPFxDVfVWLVSBqhdPeUHtb5](/images/donation-bitcoin.png)<br />19YoCcuruuovPFxDVfVWLVSBqhdPeUHtb5</center> |
