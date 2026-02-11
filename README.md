# FiveM NetCheat

## DISCLAIMER
This software should serve a legititimate purpose only! It is a Man-in-the-Middle framework for testing the security of all applications/games using the ENet UDP communication layer. You should only ever use it on servers on which you have proper authorization to do so. Unauthorized exploitation is illegal, against ToS and may get you banned.

## How to use?
 - Install Python3.10
 - `python -m pip install -r requirements.txt`
 - `python main.py [UPSTREAM IP:PORT]`

If running on Windows, you can also use the supplied binary file from releases.

## How it works?
This tool establishes a Man-in-the-Middle proxy for ENet. It may be thought of as a transparent layer connecting you to the server. This enables fully parsing all the events on the ENet network and also modifying them and creating your own. TCP packets and UDP non-ENet packets are just passed through.