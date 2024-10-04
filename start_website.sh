#!/bin/bash

# Navigate to the project directory
cd /home/wotlk_webserver/AzerothCore-website

# Activate the virtual environment
source venv/bin/activate

# Run the Flask app
python3 website.py

# Deactivate the virtual environment when done
deactivate
