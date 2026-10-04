require "test_helper"
require "socket"

class Net::NTP::TestProbe < Minitest::Test
  NTP_ADJ = 2_208_988_800

  def ntp_timestamp(unix_time)
    ntp = unix_time.to_r + NTP_ADJ
    secs = ntp.floor
    [secs & 0xFFFFFFFF, ((ntp - secs) * 2**32).floor].pack("NN")
  end

  def reply(request, li: 0, version: 4, mode: 4, stratum: 2, refid: [192, 0, 2, 1].pack("C4"), originate: request[40, 8], receive: Time.now.to_f, transmit: Time.now.to_f)
    [(li << 6) | (version << 3) | mode, stratum, 6, -20] \
      .pack("C3c") \
        + [0, 0].pack("NN") \
        + refid \
        + ntp_timestamp(receive) \
        + originate \
        + ntp_timestamp(receive) \
        + ntp_timestamp(transmit)
  end

  def with_server(host = "127.0.0.1")
    server = UDPSocket.new(Addrinfo.udp(host, 0).afamily)
    server.bind(host, 0)
    requests = Queue.new

    thread = Thread.new do
      request, (_, peer_port, peer) = server.recvfrom(1024)
      requests << request
      response = yield request
      server.send(response, 0, peer, peer_port) if response
    end
    thread.report_on_exception = false

    @requests = requests
    (@cleanups ||= []) << -> {
      thread.join(1)
      server.close unless server.closed?
    }
    server.addr[1]
  end

  def teardown
    @cleanups&.each(&:call)
  end

  def probe(port, host: "127.0.0.1", timeout: 1)
    Net::NTP.probe(host, port: port, timeout: timeout)
  end

  def unused_port(host = "127.0.0.1")
    socket = UDPSocket.new(Addrinfo.udp(host, 0).afamily)
    socket.bind(host, 0)
    socket.addr[1]
  ensure
    socket&.close
  end

  def test_that_it_has_a_version_number
    refute_nil ::Net::NTP::Probe::VERSION
  end

  def test_defaults
    assert_equal 123, Net::NTP::Probe::PORT
    assert_equal 5, Net::NTP::Probe::TIMEOUT
  end

  def test_request_is_sntp_client_packet
    port = with_server { |req| reply(req) }
    probe(port)
    request = @requests.pop

    assert_equal 48, request.bytesize
    assert_equal 3, request.getbyte(0) & 0x07
    assert_equal 4, (request.getbyte(0) >> 3) & 0x07
  end

  def test_time
    receive = Time.now.to_f + 3600.25
    transmit = receive + 0.5
    port = with_server { |req| reply(req, receive: receive, transmit: transmit) }
    result = probe(port)

    assert result.ok?
    assert_equal :ok, result.status
    assert_nil result.error
    assert_equal "127.0.0.1", result.address
    assert_equal 2, result.stratum
    assert_equal "192.0.2.1", result.reference_id
    assert_in_delta transmit, result.time.to_f, 1e-6
    assert_equal result.time.iso8601, result.to_s
  end

  def test_time_across_ntp_era_rollover
    [Time.utc(2036, 2, 7, 6, 28, 15), Time.utc(2036, 2, 7, 6, 28, 16.5r), Time.utc(2040, 1, 1)].each do |time|
      port = with_server { |req| reply(req, receive: time.to_f, transmit: time.to_f) }

      assert_equal time, probe(port).time
    end
  end

  def test_request_carries_no_client_time
    request = Net::NTP::Probe.send(:request)

    assert_equal ?\0 * 39, request[1, 39]
    refute_equal ntp_timestamp(Time.now.to_i)[0, 4], request[40, 4]
  end

  def test_request_transmit_timestamp_is_random
    transmits = Array.new(3) { Net::NTP::Probe.send(:request)[40, 8] }

    assert_equal 3, transmits.uniq.size
    refute_includes transmits, ?\0 * 8
  end

  def test_offset_and_delay
    port = with_server do |req|
      sleep 0.05
      receive = Time.now.to_f + 12.345
      transmit = Time.now.to_f + 12.345
      sleep 0.05
      reply(req, receive: receive, transmit: transmit)
    end
    result = probe(port)

    assert result.ok?
    assert_in_delta 12.345, result.offset, 0.01
    assert_in_delta 0.1, result.delay, 0.02
  end

  def test_failure_has_no_offset_or_delay
    port = with_server { nil }
    result = probe(port, timeout: 0.2)

    assert_nil result.offset
    assert_nil result.delay
  end

  def test_stratum_one_reference_id_is_ascii
    port = with_server { |req| reply(req, stratum: 1, refid: "GPS\0") }
    result = probe(port)

    assert_equal :ok, result.status
    assert_equal "GPS", result.reference_id
  end

  def test_unchecked_reply_fields
    port = with_server { |req| reply(req, li: 3, version: 7, stratum: 16) }

    assert_equal :ok, probe(port).status
  end

  def test_originate_mismatch_is_malformed
    port = with_server { |req| reply(req, originate: ("\xFF" * 8).b) }
    result = probe(port)

    assert_equal :malformed, result.status
    assert_match(/originate/, result.error)
    assert_nil result.time
  end

  def test_kiss_of_death_with_originate_mismatch_is_malformed
    port = with_server { |req| reply(req, stratum: 0, refid: "RATE", originate: ("\xFF" * 8).b) }

    assert_equal :malformed, probe(port).status
  end

  def test_non_server_mode_is_malformed
    [3, 5].each do |mode|
      port = with_server { |req| reply(req, mode: mode) }
      result = probe(port)

      assert_equal :malformed, result.status
      assert_match(/mode #{mode}/, result.error)
    end
  end

  def test_kiss_of_death
    port = with_server { |req| reply(req, stratum: 0, refid: "RATE") }
    result = probe(port)

    refute result.ok?
    assert_equal :kiss_of_death, result.status
    assert_equal 0, result.stratum
    assert_equal "RATE", result.reference_id
    assert_nil result.time
    assert_equal "kiss-o'-death RATE", result.to_s
  end

  def test_deny_and_rstr_are_kiss_of_death
    %w[DENY RSTR].each do |code|
      port = with_server { |req| reply(req, stratum: 0, refid: code) }
      result = probe(port)

      assert_equal :kiss_of_death, result.status
      assert_equal code, result.reference_id
    end
  end

  def test_unsynchronized_stratum_zero_is_ok
    port = with_server { |req| reply(req, li: 3, stratum: 0, refid: ?\0 * 4) }
    result = probe(port)

    assert result.ok?
    refute result.synchronized?
    assert_equal 0, result.stratum
    assert_nil result.reference_id
    refute_nil result.time
  end

  def test_informational_kiss_code_is_ok
    port = with_server { |req| reply(req, stratum: 0, refid: "INIT") }
    result = probe(port)

    assert result.ok?
    refute result.synchronized?
    assert_equal "INIT", result.reference_id
  end

  def test_stratum_zero_with_zero_transmit_timestamp_is_malformed
    port = with_server do |req|
      packet = reply(req, stratum: 0, refid: "INIT")
      packet[40, 8] = ?\0 * 8
      packet
    end

    assert_equal :malformed, probe(port).status
  end

  def test_zero_reference_id_is_nil
    port = with_server { |req| reply(req, stratum: 2, refid: ?\0 * 4) }
    result = probe(port)

    assert result.ok?
    assert_nil result.reference_id
  end

  def test_short_packet_is_malformed
    port = with_server { |req| reply(req)[0, 47] }
    result = probe(port)

    refute result.ok?
    assert_equal :malformed, result.status
    assert_equal "malformed reply", result.to_s
  end

  def test_tiny_packet_is_malformed
    port = with_server { "\x1c" }

    assert_equal :malformed, probe(port).status
  end

  def test_zero_transmit_timestamp_is_malformed
    port = with_server do |req|
      packet = reply(req)
      packet[40, 8] = ?\0 * 8
      packet
    end
    result = probe(port)

    refute result.ok?
    assert_equal :malformed, result.status
    assert_nil result.time
    assert_equal "malformed reply", result.to_s
  end

  def test_timeout
    port = with_server { nil }
    result = probe(port, timeout: 0.2)

    refute result.ok?
    assert_equal :no_response, result.status
    assert_match(/timeout/, result.error)
    assert_equal "no response", result.to_s
  end

  def test_refused
    result = probe(unused_port)

    assert_equal :no_response, result.status
    assert_match(/refused/i, result.error)
  end

  def test_unresolvable_host
    result = Net::NTP.probe("host.invalid", timeout: 1)

    refute result.ok?
    assert_equal :unresolved, result.status
    assert_nil result.address
    assert_equal "unresolved", result.to_s
  end

  def test_socket_creation_failure
    result = Socket.stub(:new, ->(*) { raise Errno::EAFNOSUPPORT }) do
      probe(unused_port)
    end

    assert_equal :no_response, result.status
    assert_match(/address family/i, result.error)
    assert_equal "127.0.0.1", result.address
  end

  def test_synchronized
    port = with_server { |req| reply(req) }
    result = probe(port)

    assert result.synchronized?
    assert_equal 0, result.leap_indicator
  end

  def test_leap_alarm_is_not_synchronized
    port = with_server { |req| reply(req, li: 3) }
    result = probe(port)

    assert result.ok?
    refute result.synchronized?
    assert_equal 3, result.leap_indicator
  end

  def test_stratum_sixteen_is_not_synchronized
    port = with_server { |req| reply(req, stratum: 16) }
    result = probe(port)

    assert result.ok?
    refute result.synchronized?
  end

  def test_failure_is_not_synchronized
    port = with_server { nil }

    refute probe(port, timeout: 0.2).synchronized?
  end

  def test_malformed_is_not_synchronized
    port = with_server { |req| reply(req)[0, 47] }

    refute probe(port).synchronized?
  end

  def test_kiss_of_death_is_not_synchronized
    port = with_server { |req| reply(req, stratum: 0, refid: "RATE") }
    result = probe(port)

    refute result.synchronized?
    assert_equal 0, result.leap_indicator
  end

  def test_ipv6
    port = with_server("::1") { |req| reply(req) }
    result = probe(port, host: "::1")

    assert result.ok?
    assert_equal "::1", result.address
  end
end
