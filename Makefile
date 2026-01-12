BINARY_NAME=ssh-monitor
BUILD_DIR=webserver
VPS_HOST=vps03
VPS_PATH=/opt/ssh-monitor
LDFLAGS=-s -w

.PHONY: build compress deploy clean

build:
	cd $(BUILD_DIR) && go build -ldflags="$(LDFLAGS)" -o ../$(BINARY_NAME) .

compress: build
	upx $(BINARY_NAME)

deploy: compress
	ssh $(VPS_HOST) "systemctl stop $(BINARY_NAME)"
	scp $(BINARY_NAME) $(VPS_HOST):$(VPS_PATH)
	ssh $(VPS_HOST) "systemctl start $(BINARY_NAME)"
	rm $(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)
