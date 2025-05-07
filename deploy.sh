#/bin/bash 

# This script is used to deploy the repo-scanner application
# It will build the docker image and push it to the docker registry including latest tag

# Usage: ./deploy.sh <docker_registry> <docker_image_name> <docker_image_tag>
# Example: ./deploy.sh myregistry.com myrepo/repo-scanner 1.0.0

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <docker_registry> <docker_image_name> <docker_image_tag>"
    exit 1
fi
# Assign arguments to variables
DOCKER_REGISTRY=$1
DOCKER_IMAGE_NAME=$2
DOCKER_IMAGE_TAG=$3
# Build the docker image
echo "Building the docker image..."
docker build -t $DOCKER_REGISTRY/$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG .
# Check if the build was successful
if [ $? -ne 0 ]; then
    echo "Docker build failed"
    exit 1
fi
# Push the docker image to the registry
echo "Pushing the docker image to the registry..."
docker push $DOCKER_REGISTRY/$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG
# Check if the push was successful
if [ $? -ne 0 ]; then
    echo "Docker push failed"
    exit 1
fi
# Tag the image with latest tag
echo "Tagging the docker image with latest tag..."
docker tag $DOCKER_REGISTRY/$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG $DOCKER_REGISTRY/$DOCKER_IMAGE_NAME:latest
# Check if the tag was successful
if [ $? -ne 0 ]; then
    echo "Docker tag failed"
    exit 1
fi
# Push the latest tag to the registry
echo "Pushing the latest tag to the registry..."
docker push $DOCKER_REGISTRY/$DOCKER_IMAGE_NAME:latest
# Check if the push was successful
if [ $? -ne 0 ]; then
    echo "Docker push latest tag failed"
    exit 1
fi

