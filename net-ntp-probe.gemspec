require_relative "lib/net/ntp/probe/version"

Gem::Specification.new do |spec|
  spec.name = "net-ntp-probe"
  spec.version = Net::NTP::Probe::VERSION
  spec.authors = ["William T. Nelson"]
  spec.email = ["35801+wtn@users.noreply.github.com"]

  spec.summary = "Dependency-free SNTPv4 client."
  spec.homepage = "https://github.com/wtn/net-ntp-probe"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/])
    end
  end
  spec.require_paths = ["lib"]
end
