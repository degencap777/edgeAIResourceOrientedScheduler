# edge-ai-resource-oriented-scheduler
# Please follow steps below to build ROS and move to the right directory

#!/bin/bash
git clone https://github.com/intel/edge-ai-resource-oriented-scheduler.git; \
cd edge-ai-resource-oriented-scheduler/; \
rm -rf vendor/ Gopkg.lock Gopkg.toml; \
go mod init intel.com/ros; \
go get intel.com/ros; \
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp arm64v8/golang:1.16 go build -v
mv /etc/edge-ai/scheduler/ros /etc/edge-ai/scheduler/ros.org
cp ros /etc/edge-ai/scheduler/ros


