#!/bin/bash
sudo chown -R root:root ./mypackage
dpkg-deb --build ./mypackage
sudo chown -R "$USER:$USER" ./mypackage
lintian ./mypackage.deb
