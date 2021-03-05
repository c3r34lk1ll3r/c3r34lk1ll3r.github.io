---
layout: single
title:  "Netgear D6220 Teardown"
date:   2021-02-09 16:06:50 +0100
categories: "Hardware"
toc: true
toc_sticky: true
toc_icon: "cog"
---

{% include figure image_path="/assets/images/netgear/robots.jpg" alt="" caption="\"_Which of the following would you
most prefer? A: a puppy, B: a pretty flower from your sweetie,
or C: a large properly formatted data file?_\"" %}

# Introduction
A few months ago, a friend of mine bought a new domestic router so I kindly accept to get rid
of the old one.

{% include figure image_path="/assets/images/netgear/router.jpg" caption="Netgear router
D6220" %}

I tried to power on and connect to the web interface, but the pages are protected by _basic authentication_.

{% include figure image_path="/assets/images/netgear/web_1.png" alt="Web server" caption="Blocked by
a _basic authorization_" %}

Indeed, I tried the default credentials (_admin/password_) but no luck.

I can ask for the password, but I want to try to hack this router and obtain access without asking
for the credentials. 

## Web attacks
My daily job is to perform _penetration tests_ (primarily against mobile applications, but,
sometimes, I do also _web PT_) so my first thought, was to try to _break_ in through the 
web application.

My first test was to check if there are pages exposed without authentication. I fired up _dirb_ but nothing
seems to be exposed. I tried also _burp automatic scan_ but, there is no vulnerability in there.

__Note__: To be honest, a page was left without authentication: _shares_. This seems like a
directory listing, but that page was empty and I think that can't be exploited.

Next, I tried a few passwords, but the router had redirect my browser to `MNU_access_setRecovery_index.htm` page.

This page allows to recover the router's password using the serial number... I can use it because I have the router
in my hand but, I didn't want to use this _shortcut_; I wanted to break into the router _without_ changing the 
password (I also noticed that maybe is possible to _brute-force_ the serial number).

{% include figure image_path="/assets/images/netgear/recover_password.png" alt="Reset password page" caption="
We can try to insert the _router serial_" %}

## Firmware
We can try to find some _hidden spot_ unpacking the firmware. Luckily, _netgear_
allows downloading firmwares from its web site.

We can directly open the [official website](https://www.netgear.com/support/download/), enter the 
_product name_ (in my case is D6220), and download the file (at the time I was experiment with this
router, the latest firmware was 1.68).

```bash
$ file D6220-V1.0.0.66_1.0.66.zip
D6220-V1.0.0.66_1.0.66.zip: Zip archive data, at least v2.0 to extract
$ unzip D6220-V1.0.0.66_1.0.66.zip
Archive:  D6220-V1.0.0.66_1.0.66.zip
  inflating: D6220-V1.0.0.66_1.0.66.chk
  inflating: D6220-V1.0.0.66_1.0.66_Release_Notes.html
$ binwalk D6220-V1.0.0.66_1.0.66.chk

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
60            0x3C            JFFS2 filesystem, big endian
```
The firmware is composed of a _header_ and a `JFFS2` filesystem.

We can easily use _binwalk_ and extract the filesystem.

Ok, there are a lot of files and I can't see a direct way to break the web (but I don't like
web security too).

What can we do next? We can try to open the board and check some hardware interfaces!

# Teardown
We can open this device and check if there is a way to connect to the hardware. To be completely honest,
my primary objective is to _read_ the data from the _NVRAM_ of the device because I noticed that
the password is stored in that memory.

It is really easy to open this device. There are only two screws located at the back of the envelope.

{% include figure image_path="/assets/images/netgear/back.jpg" caption="Back of the router" %}

We can unscrew these and open the envelope easily. Now, we can remove the WiFi antennas and 
remove the board from the plastic.

As I said my goal is to read the data from the _NVRAM_, but I noticed that there are four _linear_
soldering nice points. I'm not a hardware expert (this is my real-world experiment honestly) but I think that it can
be interesting to look closely at that PINs.


{% include figure image_path="/assets/images/netgear/serial.jpg" alt="Board" caption="In the red circle 
I soldered four PIN in order to connect to that port" %}

So, we can easily resolder the PIN and see what happens there (sorry but I’d think to take a photo without the soldered PIN).

{% include figure image_path="/assets/images/netgear/serial_2.jpg" caption="PIN zoomed" %}

Indeed, as you can see, I'm very bad at soldering but using a tester we can check that, at least, 
there is no short-circuit and try to understand how that PINs are connected to the board.

We can try to search if there is some GND PIN using the tester and checking if there is a PIN connected
to the GND of the power source (it is not always so simple but it's a 0-time check).

We are lucky because the second pin (from the inside of the board) is directly connected to GND!

We can attach cables to these PINs and port the signal to a breadboard so it is easier to make 
connections.

Now that we have found a _GND_ and we have a stable point of connection, we can check the signals with a _logic analyzer_.

{% include figure image_path="/assets/images/netgear/pin_bread.jpg" caption="Connection of the board to a breadboard" %}

## Logic Analyzer
Now we should _listen_ if there are some signals in those PINs. We can do it using a _logic analyzer_
that ["is an electronic instrument that captures and displays multiple signals from a digital system or digital circuit"](https://en.wikipedia.org/wiki/Logic_analyzer).

I have a "[Saleae Logic 8](https://www.saleae.com/)" but there are [others cheaper device](https://www.sparkfun.com/products/15033) that
can work on this device.

{% include figure image_path="/assets/images/netgear/salea.jpg" caption="Saleae connected to PIN throught the breadboard" %}

We can connect the _GND_ signal of the logic analyzer to `PIN1` and the signal channel to other PINs.

The connection can be summarized as:

| PIN | Purpose | Channel (logic analyzer) |
| --- | ------- | ------------------------ |
| 0   | ?       | 0                        |
| 1   | GND     | GND(all channel)         |
| 2   | ?       | 1                        |
| 3   | ?       | 2                        |

I count as the `PIN0` the farthest to the edge of the board.

Using the _saleae software_, we can start our analysis by reading the _analogic value_.

{% include figure image_path="/assets/images/netgear/analog_start1.png" caption="There are a lot of traffics in channel 0" %}

As we can see, there are a lot of traffics on `PIN0` (channel 0, the upper) meanwhile the others are steady. 
Now, we can switch to capture data in _digital_ (to be honest, I don't know if passing by the analog phase is useful
but I'd like to think that more information I get is better).

{% include figure image_path="/assets/images/netgear/s_digital.png" caption="Now we have digital data" %}

The logic analyzer has an amazing feature: the __protocol decoder__. 

We can try to abstract the electrical value of these signals and decode as a digital protocol.

My first idea (and hope) is that is _serial protocol_, so we can add that decoder. There are various
configuration that we don't known, the mostly important is _bit/s_.

Our first try can be with the default value (baud rate at 9600) but the decoder _fails_ and we obtain
only _frame error_. 

We can _brute-foce_ this value in order to try different values, at least with the default value. 
One of the most common baud rate is 115200. 

With 115200 we decode everything! And we obtain ASCII data, which seems like a bootloader.

{% include figure image_path="/assets/images/netgear/s_decoded.png" caption="The decoder is able to reconstruct the frame" %}

We can update our pins table:

| PIN | Purpose | Channel (logic analyzer) |
| --- | ------- | ------------------------ |
| 0   | S_TX    | 0                        |
| 1   | GND     | GND(all channel)         |
| 2   | ?       | 1                        |
| 3   | ?       | 2                        |


We can read all the serial data from the logic analyzer but it's not so comfortable, we need 
another board.

## Bus Pirate
I use the [bus pirate](toinsert) but any board with serial communication will do the work.

Reading the documentation of the _bus pirate_, we can search for the pin-out in order to use
the serial port. 

The pin-out of the board is:
- `MISO` -> TX of the serial port (so the output of the router, `PIN0`)
- `MOSI` -> RX of the serial port (so the input of the router)
- `GND` -> `GND` of the board (`PIN1`)

We know how to connect `MISO` pin, but for `MOSI`? We have only two pins free so we can try with the
first one (`PIN2`).

{% include figure image_path="/assets/images/netgear/bus_pirate.jpg" caption="Connection of the Bus Pirate" %}

We can connect with bus pirate using `screen` (or other terminals).

```bash
sudo screen /dev/ttyUSB0 115200
```
The bus pirate needs to be correctly set before using it.

{% include figure image_path="/assets/images/netgear/bus_pirate1.png" %}

We can leave the other settings to the default value (we should use the same settings as the 
logic analyzer used to decode the signal).

Now that we have correctly configured the bus, we can set the _correct mode_ and power on the device.

{% include figure image_path="/assets/images/netgear/bus_pirate2.png" %}

## Console
As soon as we power on the device, we will see the bootloader and the kernel power up!

{% include figure image_path="/assets/images/netgear/bootloader.png" %}

We can try to hit some enter in order to check if the `MOSI` is correct: if our data is echoed out we 
have a fully bidirectional console port!

After the boot, the firmware will land on a _busybox_ shell, and our privilege? `admin` of course!

{% include figure image_path="/assets/images/netgear/win.png" %}


# Getting the passwords
Now we have a terminal on the device, with `admin` privilege so we are happy already but we want 
to access the web portal of the router. 

As I said previously, that password is stored in the NVRAM (as I know is another story for another post)
and if we look in the filesystem, we can find an amazing binary: `nvram`. 

This software allows us to extract data from the NVRAM extremely easily... So, now it is incredibly simple
to extract the HTTP password. As simple as: `./nvram show http`

{% include figure image_path="/assets/images/netgear/http_password.png" caption="And now we have http user and password" %}

So we win! But we can do a step further: the ADSL credentials. 


{% include figure image_path="/assets/images/netgear/adsl_password.png" caption="And now we have http user and password" %}

# Conclusion
We have obtained the password using an hardware attack, because the serial port is left opened
and easily resoldered.
