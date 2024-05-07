#!/bin/bash

# ANSI escape codes for text formatting
BOLD=$(tput bold)
RESET=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)

echo
echo -e "${BOLD}${GREEN}WELCOME TO PENGUIN${RESET}\n"

echo -e "You're in an interactive Docker shell. For a smoother experience, consider using PENGUIN directly from your host machine with the following steps:\n"

echo -e "${BOLD}${RED}Step 1: Exit this shell${RESET}\n"
echo -e "To exit, type:\n"
echo -e "exit 0\n"

echo -e "${BOLD}${RED}Step 2: Install PENGUIN${RESET}\n"
echo -e "To install PENGUIN on your host machine, choose one of the following options:\n"

echo -e "- ${BOLD}System-wide Installation:${RESET} This makes the penguin command available to all users:\n"
echo -e "  docker run rehosting/penguin penguin_install | sudo sh"

echo -e "- ${BOLD}Local Installation:${RESET} This makes penguin command available to your user\n"
echo -e "  docker run rehosting/penguin penguin_install.local | sh"

echo -e "${BOLD}${RED}Step 3: Run PENGUIN${RESET}\n"
echo -e "You can now run PENGUIN. For examples and usage information run:"
echo -e "penguin --help\n"

