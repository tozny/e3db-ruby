FROM ruby:2.2-alpine

RUN mkdir -p /src
WORKDIR /src/

COPY . /src/
RUN rm *.gem && gem build e3db.gemspec && gem install e3db

RUN apk add --no-cache git libsodium-dev gcc make musl-dev

ENTRYPOINT ["/src/integration.rb"]
