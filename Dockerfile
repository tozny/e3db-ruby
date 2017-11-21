FROM ruby:2.2-alpine

RUN apk add --no-cache git libsodium-dev gcc make musl-dev

RUN mkdir -p /src
WORKDIR /src/

COPY . /src/
RUN rm -f *.gem && gem build e3db.gemspec && gem install e3db

ENTRYPOINT ["/src/integration.rb"]
