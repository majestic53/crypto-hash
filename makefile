# crypto-hash
# Copyright (C) 2015 David Jolly
# ----------------------
#
# crypto-hash is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# crypto-hash is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CC=clang
EXE=crypto_hash
FLAGS=-march=native -O3 -Wall
JOB_SLOTS=1
LIB=libcryptohash.a
OUT_BIN=./bin/
OUT_BUILD=./build/
SRC_DIR=./src/
TOP=./

all: build

build: clean init lib exe

clean:
	rm -rf $(OUT_BIN)
	rm -rf $(OUT_BUILD)

exe:
	@echo ""
	@echo "============================================"
	@echo "BUILDING EXECUTABLE(S)"
	@echo "============================================"
	$(CC) $(FLAGS) $(TOP)main.c $(OUT_BUILD)$(LIB) -o $(OUT_BIN)$(EXE)

init:
	mkdir $(OUT_BIN)
	mkdir $(OUT_BUILD)

lib: 
	@echo ""
	@echo "============================================"
	@echo "BUILDING LIBRARIE(S)"
	@echo "============================================"
	cd $(SRC_DIR) && make build -j $(JOB_SLOTS)
	cd $(SRC_DIR) && make archive
