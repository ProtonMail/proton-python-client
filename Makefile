.PHONY: image latest latest-tag test deploy-local local login-deploy

-include .env

branch ?= master
DOCKERFILE_BUILD=/tmp/Dockerfile.image
NAME_IMAGE ?= "$(CI_REGISTRY_IMAGE)/$(src)"
TAG_IMAGE := branch-$(subst /,-,$(branch))

# We use :latest so we can use somewhere else, but it's the same as branch-master the other one is for CI
ifeq ($(branch), latest)
	TAG_IMAGE=latest
endif

IMAGE_URL_DEB = ubuntu:latest
IMAGE_URL_FED33 = fedora:33
IMAGE_URL_FED34 = fedora:34
IMAGE_URL_FED35 = fedora:35
IMAGE_URL_ARCH = archlinux:latest
IMAGE_URL_OPENSUSE_LEAP_153 = opensuse/leap:15.3

base: image-deb image-fed33 image-fed34 image-fed35 image-arch image-opensuse-leap-153

# Create the image based on ubuntu
image-deb: image
image-deb: DOCKER_FILE_SOURCE = Dockerfile.deb
image-deb: src = ubuntu

# Create the image based on archlinux
image-arch: image
image-arch: DOCKER_FILE_SOURCE = Dockerfile.arch
image-arch: src = archlinux

# Create the image based on opensuse leap 15.3
image-arch: image
image-arch: DOCKER_FILE_SOURCE = Dockerfile.opensuse-leap-153
image-arch: src = opensuse-leap-153

# Create the image based on fedora 33
image-fed33: image
image-fed33: DOCKER_FILE_SOURCE = Dockerfile.fed33
image-fed33: src = fedora33

# Create the image based on fedora 34
image-fed34: image
image-fed34: DOCKER_FILE_SOURCE = Dockerfile.fed34
image-fed34: src = fedora34

# Create the image based on fedora 35
image-fed35: image
image-fed35: DOCKER_FILE_SOURCE = Dockerfile.fed35
image-fed35: src = fedora35

## Make remote image form a branch make image branch=<branchName> (master default)
image: requirements.txt docker-source
	docker build -t $(NAME_IMAGE):$(TAG_IMAGE) -f "$(DOCKERFILE_BUILD)" .
	docker push $(NAME_IMAGE):$(TAG_IMAGE)
	docker tag $(NAME_IMAGE):$(TAG_IMAGE) $(NAME_IMAGE):$(TAG_IMAGE)

## We host our own copy of the image ubuntu:latest
docker-source:
	sed "s|IMAGE_URL_FED33|$(IMAGE_URL_FED33)|; s|IMAGE_URL_FED34|$(IMAGE_URL_FED34)|; s|IMAGE_URL_FED35|$(IMAGE_URL_FED35)|; s|IMAGE_URL_DEB|$(IMAGE_URL_DEB)|; s|IMAGE_URL_OPENSUSE_LEAP_153|$(IMAGE_URL_OPENSUSE_LEAP_153)|; s|IMAGE_URL_ARCH|$(IMAGE_URL_ARCH)|" $(DOCKER_FILE_SOURCE) > /tmp/Dockerfile.image

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

local-base: local-deb local-fed33 local-fed34 local-fed35 local-arch image-opensuse-leap-153

local-deb: local
local-deb: DOCKER_FILE_SOURCE = Dockerfile.deb

local-fed33: local
local-fed33: DOCKER_FILE_SOURCE = Dockerfile.fed33

local-fed34: local
local-fed34: DOCKER_FILE_SOURCE = Dockerfile.fed34

local-fed35: local
local-fed35: DOCKER_FILE_SOURCE = Dockerfile.fed35

local-opensuse-leap-153: local
local-opensuse-leap-153: DOCKER_FILE_SOURCE = Dockerfile.opensuse-leap-153

local-arch: local
local-arch: DOCKER_FILE_SOURCE = Dockerfile.arch

# Build an image from your computer and push it to our repository
deploy-local: login-deploy build tag push

# If you want to deploy an image to our registry you will need to set these variables inside .env
login-deploy:
	docker login -u "$(CI_DEPLOY_USER)" -p "$(CI_JOB_TOKEN)" "$(CI_REGISTRY)"

######### Not linked to the image ###############

## Run tests against the latest version of the image from your code
test-deb: local-deb
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest

## Run tests against the latest version of the image from your code

test-fed33: local-fed33
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest

test-fed34: local-fed34
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest

test-fed35: local-fed35
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest

## Run tests against the latest version of the image from your code
test-arch: local-arch
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest

## Run tests against the latest version of the image from your code
test-opensuse-leap-15-3: local-arch
	# Keep -it because with colors it's better
	@ docker run \
			--rm \
			-it \
			--privileged \
			--volume $(PWD)/.env:/home/user/proton-python-client.env \
			proton-python-client:latest \
			python3 -m pytest
