BINARY_NAME=ssh-monitor
BINARY_TMP=$(BINARY_NAME).tmp
BUILD_DIR=webserver
VPS_HOST=vps03
VPS_PATH=/opt/ssh-monitor
LDFLAGS=-s -w

.PHONY: build build-linux compress deploy clean

build:
	cd $(BUILD_DIR) && go build -ldflags="$(LDFLAGS)" -o ../$(BINARY_NAME) .

build-linux:
	cd $(BUILD_DIR) && GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o ../$(BINARY_TMP) .

compress: build-linux
	upx $(BINARY_TMP)

deploy: compress
	ssh $(VPS_HOST) "systemctl stop $(BINARY_NAME)"
	scp $(BINARY_TMP) $(VPS_HOST):$(VPS_PATH)/$(BINARY_NAME)
	ssh $(VPS_HOST) "chmod +x $(VPS_PATH)/$(BINARY_NAME) && systemctl start $(BINARY_NAME)"
	rm $(BINARY_TMP)

clean:
	rm -f $(BINARY_NAME) $(BINARY_TMP)
