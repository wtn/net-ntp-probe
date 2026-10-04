require "socket"
require "time"
require_relative "probe/version"

module Net
  module NTP
    def self.probe(host, port: Probe::PORT, timeout: Probe::TIMEOUT)
      Probe.call host, port: port, timeout: timeout
    end

    module Probe
      PORT = 123
      TIMEOUT = 5
      NTP_ADJ = 2_208_988_800
      KISS_CODES = %w[DENY RSTR RATE].freeze

      Result = Data.define(:status, :error, :address, :leap_indicator, :stratum, :reference_id, :time, :offset, :delay) do
        def self.failure(status, error, **fields)
          new(**members.to_h {|m| [m, nil] }, status: status, error: error, **fields)
        end

        def ok?
          status == :ok
        end

        # Server answered and claims a synchronized clock.
        def synchronized?
          ok? && leap_indicator != 3 && stratum.between?(1, 15)
        end

        def to_s
          case status
          when :unresolved then "unresolved"
          when :no_response then "no response"
          when :malformed then "malformed reply"
          when :kiss_of_death then "kiss-o'-death #{reference_id}"
          else time.iso8601
          end
        end
      end

      def self.call(host, port: PORT, timeout: TIMEOUT)
        host.to_s.empty? and raise ArgumentError, "host required"

        begin
          addrinfo = Addrinfo.getaddrinfo(host, port, nil, :DGRAM).first
        rescue SocketError => e
          return Result.failure(:unresolved, e.message)
        end
        address = addrinfo.ip_address
        packet = request

        begin
          socket = Socket.new addrinfo.afamily, Socket::SOCK_DGRAM
          socket.connect addrinfo
          sent_at = Process.clock_gettime Process::CLOCK_REALTIME, :nanosecond
          started = Process.clock_gettime Process::CLOCK_MONOTONIC, :nanosecond
          socket.send packet, 0
          unless socket.wait_readable(timeout)
            return Result.failure(:no_response, "timeout after #{timeout}s", address: address)
          end
          data = socket.recv 1024
          # Elapsed monotonic time, so a clock step mid-request cannot skew it.
          received_at = sent_at + Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - started
        rescue SystemCallError => e
          return Result.failure(:no_response, e.message, address: address)
        ensure
          socket&.close
        end

        evaluate(data, packet.byteslice(40, 8), address, Rational(sent_at, 1_000_000_000), Rational(received_at, 1_000_000_000))
      end

      def self.request
        [0b00_100_011].pack(?C) + (?\0 * 39) + Random.urandom(8)
      end

      def self.evaluate(data, originate, address, t1, t4)
        if data.bytesize < 48
          return Result.failure(:malformed, "short packet (#{data.bytesize} bytes)", address: address)
        end

        mode = data.getbyte(0) & 0x07
        if mode != 4
          return Result.failure(:malformed, "unexpected mode #{mode}", address: address)
        end

        if data.byteslice(24, 8) != originate
          return Result.failure(:malformed, "originate timestamp mismatch", address: address)
        end

        leap_indicator = data.getbyte(0) >> 6
        stratum = data.getbyte 1
        reference_id = reference_id stratum, data.byteslice(12, 4)
        if stratum == 0 && KISS_CODES.include?(reference_id)
          return Result.failure(:kiss_of_death, "kiss-o'-death #{reference_id}", address: address, leap_indicator: leap_indicator, stratum: stratum, reference_id: reference_id)
        end

        if data.byteslice(40, 8) == ?\0 * 8
          return Result.failure(:malformed, "zero transmit timestamp", address: address, leap_indicator: leap_indicator, stratum: stratum, reference_id: reference_id)
        end

        t2 = timestamp data.byteslice(32, 8)
        t3 = timestamp data.byteslice(40, 8)
        offset = ((t2 - t1) + (t3 - t4)) / 2
        delay = (t4 - t1) - (t3 - t2)

        Result.new status: :ok, error: nil, address: address, leap_indicator: leap_indicator, stratum: stratum, reference_id: reference_id, time: Time.at(t3), offset: offset.to_f, delay: delay.to_f
      end

      def self.timestamp(bytes)
        secs, frac = bytes.unpack "NN"
        secs += 2**32 if secs < 2**31
        secs - NTP_ADJ + Rational(frac, 2**32)
      end

      def self.reference_id(stratum, refid)
        return if refid == ?\0 * 4

        if stratum < 2
          refid.delete ?\0
        else
          refid.unpack("C4").join ?.
        end
      end

      private_class_method :request, :evaluate, :timestamp, :reference_id
    end
  end
end
