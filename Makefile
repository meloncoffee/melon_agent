MODULE_PATH=github.com/meloncoffee/melon_agent
VERSION=0.9.0
BUILD_TIME=$(shell date +%Y-%m-%d' '%H:%M:%S)

BIN_DIR=bin
CONF_DIR=conf
CONF_FILE=melon_agent.yaml

LDFLAGS=-X '${MODULE_PATH}/config.BuildTime=${BUILD_TIME}' \
		-X '${MODULE_PATH}/config.Version=${VERSION}'

define go_build
	mkdir -p ${BIN_DIR}/${CONF_DIR}
	go build -o ${BIN_DIR}/${MODULE_NAME} -ldflags "${LDFLAGS}"
	cp -f config/${CONF_FILE} ${BIN_DIR}/${CONF_DIR}/${CONF_FILE}
endef

all: init build

init:
	@if [ ! -f go.mod ]; then \
		echo "Initialize Go Module..."; \
		go mod init ${MODULE_PATH}; \
		go mod tidy; \
	fi
	
deps:
	@if [ -f go.mod ]; then \
		echo "Installing Dependencies..."; \
		go mod tidy; \
	fi

build:
	@echo "Building Project..."
	$(call go_build)

clean:
	@echo "Cleaning up..."
	rm -rf ${BIN_DIR}

.PHONY: init deps build clean
