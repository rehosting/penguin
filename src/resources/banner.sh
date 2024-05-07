#!/bin/bash

# ANSI escape codes for text formatting
if [ -t 0 ]; then
    BOLD=$(tput bold)
    RESET=$(tput sgr0)
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    INTERACTIVE=true
    STARS=""
else
    BOLD=""
    STARS="**" # Alternative when no colors available
    RESET=""
    RED=""
    GREEN=""
    INTERACTIVE=false
fi

echo
echo -e "${BOLD}${GREEN}Welcome to the penguin container${RESET}\n"

echo -e "We recommend using this container through our ${GREEN}penguin${RESET} CLI utility on your host machine."
echo -e "Follow the instructions below to install the utility and run it on your host machine.\n"

if $INTERACTIVE; then
    # If in a terminal, print instructions to exit the shell
    echo -e "${BOLD}${RED}${STARS}Step 0: If you are in an interactive docker shell, exit it${RESET}${STARS}"
    echo -e "  # exit\n"
fi

echo -e "${BOLD}${RED}${STARS}Step 1: Install ${GREEN}penguin${RESET}${STARS}\n"
echo -e "To install ${GREEN}penguin${RESET} on your host machine, choose one of the following options:\n"

echo -e "- ${BOLD}System-wide Installation:${RESET} This makes the ${GREEN}penguin${RESET} command available to all users:"
echo -e "  $ docker run rehosting/penguin penguin_install | sudo sh\n"

echo -e "- ${BOLD}Local Installation:${RESET} This makes ${GREEN}penguin${RESET} command available to your user"
echo -e "  $ docker run rehosting/penguin penguin_install.local | sh\n"

echo -e "${BOLD}${RED}${STARS}Step 2: Run ${GREEN}penguin${RESET}${STARS}"
echo -e "  $ penguin --help\n"

