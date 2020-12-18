.PHONY: image latest latest-tag test deploy-local local login-deploy

-include .env

branch ?= master
DOCKERFILE_BUILD=/tmp/Dockerfile.image
NAME_IMAGE ?= "$(CI_REGISTRY_IMAGE)"
TAG_IMAGE := branch-$(subst /,-,$(branch))-$(src)

# We use :latest so we can use somewhere else, but it's the same as branch-master the other one is for CI
ifeq ($(branch), latest)
	TAG_IMAGE=latest
endif


IMAGE_URL_DEB ?= $(CI_REGISTRY_IMAGE_PROTON)/ubuntu:latest
IMAGE_URL_RPM ?= $(CI_REGISTRY_IMAGE_PROTON)/fedora:latest
ifndef CI_REGISTRY_IMAGE_PROTON
 	IMAGE_URL_DEB = ubuntu:latest
  	IMAGE_URL_RPM = fedora:latest
endif

# Run make base to build both images based on ubuntu and fedora
base: image-deb image-rpm

# Create the image based on ubuntu
image-deb: image
image-deb: DOCKER_FILE_SOURCE = Dockerfile.deb
image-deb: src = ubuntu

# Create the image based on fedora
image-rpm: image
image-rpm: DOCKER_FILE_SOURCE = Dockerfile.rpm
image-rpm: src = fedora

## Make remote image form a branch make image branch=<branchName> (master default)
image: requirements.txt docker-source
	docker build -t $(NAME_IMAGE):$(TAG_IMAGE) -f "$(DOCKERFILE_BUILD)" .
	docker push $(NAME_IMAGE):$(TAG_IMAGE)
	docker tag $(NAME_IMAGE):$(TAG_IMAGE) $(NAME_IMAGE):$(TAG_IMAGE)

## We host our own copy of the image ubuntu:latest
docker-source:
	sed "s|IMAGE_URL_RPM|$(IMAGE_URL_RPM)|; s|IMAGE_URL_DEB|$(IMAGE_URL_DEB)|" $(DOCKER_FILE_SOURCE) > /tmp/Dockerfile.image

requirements.txt:
	@ touch requirements.txt

# Tag the image branch-master as latest
latest:
	docker pull $(NAME_IMAGE):branch-master-$(src)	
	docker tag $(NAME_IMAGE):branch-master-$(src)  $(NAME_IMAGE):latest-$(src)
	docker push $(NAME_IMAGE):latest-$(src)

## Build image on local -> name nm-core:latest
local: docker-source
	# docker build -t "$(NAME_IMAGE)" -f "$(DOCKERFILE_BUILD)" .
	docker build -t $(NAME_IMAGE) -f "$(DOCKERFILE_BUILD)" .
	@ rm -rf __SOURCE_APP || true
local: NAME_IMAGE = proton-python-client:latest

local-base: local-deb local-rpm

local-deb: local
local-deb: DOCKER_FILE_SOURCE = Dockerfile.deb

local-rpm: local
local-rpm: DOCKER_FILE_SOURCE = Dockerfile.rpm

# Build an image from your computer and push it to our repository
deploy-local: login-deploy build tag push

# If you want to deploy an image to our registry you will need to set these variables inside .env
login-deploy:
	docker login -u "$(CI_DEPLOY_USER)" -p "$(CI_JOB_TOKEN)" "$(CI_REGISTRY)"

######### Not linked to the image ###############

## Run tests against the latest version of the image from your code
test: local
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest
