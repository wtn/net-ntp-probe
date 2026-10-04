# Net::NTP::Probe

Dependency-free SNTPv4 client Ruby gem.

NB: Only the first resolved address is tried.

## Usage

```ruby
require "net/ntp/probe"

result = Net::NTP.probe("pool.ntp.org")  # => #<data Net::NTP::Probe::Result …>
result.ok?     # => true (server answered)
result.synchronized? # => true (server answered and claims a synchronized clock)
result.time    # => 2026-10-04 15:57:25 2101236257/2147483648 -0000
result.offset  # => 0.008670320288978517
result.delay   # => 0.05344587983332574

result = Net::NTP.probe("localhost", port: 65535, timeout: 1)
result.ok?     # => false
result.status  # => :no_response
result.error   # => "Connection refused - recvfrom(2)"

result = Net::NTP.probe("host.invalid")
result.status  # => :unresolved
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/wtn/net-ntp-probe.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
