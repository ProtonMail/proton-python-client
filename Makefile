.PHONY: image copy-app latest latest-tag test deploy-local local login-deploy

-include .env

branch ?= master
NAME_IMAGE ?= "$(CI_REGISTRY_IMAGE)"
TAG_IMAGE := branch-$(subst /,-,$(branch))

# We use :latest so we can use somewhere else, but it's the same as branch-master the other one is for CI
ifeq ($(branch), latest)
	TAG_IMAGE=latest
endif


IMAGE_URL ?= $(CI_REGISTRY)/ubuntu:latest            
ifndef CI_REGISTRY                                   
	IMAGE_URL = 'ubuntu:latest'                        
endif  

## Make remote image form a branch make image branch=<branchName> (master default)
image: requirements.txt copy-app
	docker build -t $(NAME_IMAGE):$(TAG_IMAGE) .
	docker push $(NAME_IMAGE):$(TAG_IMAGE)
	docker tag $(NAME_IMAGE):$(TAG_IMAGE) $(NAME_IMAGE):$(TAG_IMAGE)

## Copy the current app and remove some items we don't need inside the image
# - .git -> huge and doesn't provide anything relevant
# - .env -> it's private
# - __SOURCE_APP -> if it exists, it should not but it's better to filter it out
copy-app:
	@ cd ..
	@ rm -rf __SOURCE_APP || true
	@ rsync \
			-avz \
			--exclude .git \
			--exclude .env \
			--exclude __SOURCE_APP \
			. __SOURCE_APP
	@ cd - > /dev/null

requirements.txt:
	@ touch requirements.txt

# Tag the image branch-master as latest
latest:
	docker pull $(NAME_IMAGE):branch-master
	docker tag $(NAME_IMAGE):branch-master $(NAME_IMAGE):latest
	docker push $(NAME_IMAGE):latest

## Build image on local -> name nm-core:latest
local: requirements.txt copy-app
	@ docker build -t "$(NAME_IMAGE)" .
	@ rm -rf __SOURCE_APP || true
local: NAME_IMAGE = proton-python-client:latest


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
