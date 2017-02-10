# Local Quality-of-Service

A final year research project into the causation of poor internet quality within the home. The application scans for all connected devices to the home router and cyclically takes measurements from the devices. The data is produced in raw format on a minute-by-minute basis, but more importantly at the end of each day a script runs to convert this data into a single standardised Quality Score over the 24 hour period. This is done to conclude my hypothesis, which I am working on currently.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Ensure you have Python 3.6 and install scapy:

```
pip3 install scapy-python3
```

### Installing

First clone repository

```
git clone https://github.com/tomcusack1/local-QoS.git
```

Ensure the shell scripts (main.sh and daily_analysis.sh) have 777 and executable priviledges and place the following records into your crontab.

```
*/5 * * * * /home/tom/src/local-QoS/main.sh > /home/tom/src/local-QoS/cron.log 2>&1
59 23 * * * /home/tom/src/local-QoS/daily_analysis.sh > /home/tom/src/local-QoS/daily_analysis.log
```

cd into the directory, and run main.py with sudo priviledges (sudo python3 main.py). The default target is set to a router with the IP address of 192.168.0.1. You can use a custom IP by placing the IP address in after the command: (sudo python3 main.py 192.168.1.1).

This will give you a manual example, without the cron job working, of 1 row of measurements. For accurate quality data to be performed, the tool should be running as a daemon for a 24 hour period.

## Running the tests

cd into <code>tests/</code> and run <code>sudo python3 -m test_suite.py</code>

## Deployment

This application is best run on a Raspberry Pi, rather than a machine, with a central location within the local environment. The emphasis has been working wirelessly, so using ethernet directly into the router will give inaccurate results. Follow the installation guide above to install/set up the app as a daemon.

## Built With

* [scapy](https://github.com/secdev/scapy) - Packet manipulation library

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

* **Tom Cusack** - *Initial work* - [Website](https://tom-cusack.com)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
