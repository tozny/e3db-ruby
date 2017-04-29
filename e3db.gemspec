# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'e3db/version'

Gem::Specification.new do |spec|
  spec.name          = "e3db"
  spec.version       = E3DB::VERSION
  spec.authors       = ["Tozny, LLC"]
  spec.email         = ["info@tozny.com"]

  spec.summary       = %q{e3db client SDK}
  #spec.description   = %q{TODO: Write a longer description or delete this line.}
  spec.homepage      = "https://tozny.com/e3db"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency 'simplecov', '~> 0.14.1'

  spec.add_dependency 'dry-struct', '~> 0.2.1'
  spec.add_dependency 'lru_redux', '~> 1.1'
  spec.add_dependency 'rbnacl', '~> 4.0', '>= 4.0.2'
  spec.add_dependency 'net-http-persistent', '~> 2.9.4'
  spec.add_dependency 'faraday_middleware', '~> 0.11.0.1'
  spec.add_dependency 'oauth2', '~> 1.3', '>= 1.3.1'
end