FROM ghcr.io/rouvald/gcc14_conan:latest

WORKDIR /app

COPY . .

RUN chmod +x compile.sh && ./compile.sh -r

# add start bin