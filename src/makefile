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
FLAGS=-march=native -O3 -Wall
INC=./include/
LIB=libcryptohash.a
OUT_BIN=./../bin/
OUT_BUILD=./../build/
SRC=./src/

all: build archive

archive:
	@echo ""
	@echo "--- BUILDING CRYPTO-HASH LIBRARY ------------------"
	ar rcs $(OUT_BUILD)$(LIB) $(OUT_BUILD)crypto_hash.o
	@echo "--- DONE ------------------------------------------"
	@echo ""

build: crypto_hash.o

crypto_hash.o: $(SRC)crypto_hash.c $(INC)crypto_hash.h
	$(CC) $(FLAGS) -c $(SRC)crypto_hash.c -o $(OUT_BUILD)crypto_hash.o
