CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -Wunused-parameter -g -fsanitize=address
LDFLAGS = -lcrypto -fsanitize=address

SRC_DIR = src
APP_DIR = apps
BUILD_DIR = build
BIN_DIR = bin

# Source files
UTILS_SRC = $(SRC_DIR)/utils.c
RANDGEN_SRC = $(SRC_DIR)/randgen.c
RSAGEN_SRC = $(SRC_DIR)/rsagen.c
RANDGEN_APP_SRC = $(APP_DIR)/randgen_app.c
RSAGEN_APP_SRC = $(APP_DIR)/rsagen_app.c

# Object files
UTILS_OBJ = $(BUILD_DIR)/utils.o
RANDGEN_OBJ = $(BUILD_DIR)/randgen.o
RSAGEN_OBJ = $(BUILD_DIR)/rsagen.o
RANDGEN_APP_OBJ = $(BUILD_DIR)/randgen_app.o
RSAGEN_APP_OBJ = $(BUILD_DIR)/rsagen_app.o

# Executables
RANDGEN = $(BIN_DIR)/randgen
RSAGEN = $(BIN_DIR)/rsagen

.PHONY: all clean directories

all: directories $(RANDGEN) $(RSAGEN)

directories:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

# Build object files
$(UTILS_OBJ): $(UTILS_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(RANDGEN_OBJ): $(RANDGEN_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(RSAGEN_OBJ): $(RSAGEN_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(RANDGEN_APP_OBJ): $(RANDGEN_APP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(RSAGEN_APP_OBJ): $(RSAGEN_APP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Build executables
$(RANDGEN): $(UTILS_OBJ) $(RANDGEN_OBJ) $(RANDGEN_APP_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(RSAGEN): $(UTILS_OBJ) $(RSAGEN_OBJ) $(RSAGEN_APP_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)