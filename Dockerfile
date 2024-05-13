# based image on gumi/erlang:20.1.1-alpine
FROM gumi/erlang:20.1.1-alpine

# Set working dir to /app
WORKDIR /ecc_compact

# Copy the current directory contents into the container at /app
COPY . /ecc_compact

# Install make
RUN apk update
RUN apk add --no-cache make gcc build-base openssl-dev