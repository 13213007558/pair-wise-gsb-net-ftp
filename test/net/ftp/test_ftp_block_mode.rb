# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "stringio"
require "socket"

class FTPBlockModeTest < Test::Unit::TestCase
  EOR = Net::FTP::BLOCK_DESCRIPTOR_EOR
  EOF_BIT = Net::FTP::BLOCK_DESCRIPTOR_EOF
  ERRORS = Net::FTP::BLOCK_DESCRIPTOR_ERRORS
  RESTART = Net::FTP::BLOCK_DESCRIPTOR_RESTART

  # An IO-ish reader that returns at most +chunk+ bytes per read call,
  # simulating network segmentation: a short read must never be
  # mistaken for a block boundary.
  class ChunkedReader
    def initialize(data, chunk)
      @io = StringIO.new(data)
      @chunk = chunk
    end

    def read(len)
      @io.read([len, @chunk].min)
    end
  end

  # Minimal stand-in for a data connection.
  class FakeConn
    def initialize(io)
      @io = io
    end

    def read(len = nil)
      len ? @io.read(len) : @io.read
    end

    def gets
      @io.gets
    end

    def write(str)
      @io.write(str)
    end

    def shutdown(*)
    end

    def read_timeout=(sec)
    end

    def close
    end
  end

  def frame(descriptor, payload = "")
    [descriptor, payload.bytesize].pack("Cn") + payload
  end

  def new_ftp
    Net::FTP.new
  end

  def retrbinary_blocks(conn, &block)
    new_ftp.send(:retrbinary_blocks, conn, &block)
  end

  def test_transfer_mode_default_is_stream
    assert_equal(Net::FTP::STREAM_MODE, new_ftp.transfer_mode)
  end

  def test_transfer_mode_normalization
    ftp = new_ftp
    ftp.transfer_mode = :block
    assert_equal(Net::FTP::BLOCK_MODE, ftp.transfer_mode)
    ftp.transfer_mode = "stream"
    assert_equal(Net::FTP::STREAM_MODE, ftp.transfer_mode)
    ftp.transfer_mode = "B"
    assert_equal(Net::FTP::BLOCK_MODE, ftp.transfer_mode)
    ftp.transfer_mode = :s
    assert_equal(Net::FTP::STREAM_MODE, ftp.transfer_mode)
    assert_raise(ArgumentError) { ftp.transfer_mode = :compressed }
  end

  def test_retrbinary_blocks_short_reads
    payload = (0..0xff).map(&:chr).join
    frames = frame(0, payload[0, 100]) +
             frame(EOR, payload[100, 100]) +
             frame(EOR | EOF_BIT, payload[200..])
    chunks = []
    retrbinary_blocks(ChunkedReader.new(frames, 1)) { |data| chunks << data }
    assert_equal([payload[0, 100], payload[100, 100], payload[200..]], chunks)
    assert_equal(payload, chunks.join)
  end

  def test_retrbinary_blocks_cross_block_payload
    payload = "hello, block mode world!"
    frames = payload.bytes.each_slice(5).map { |slice|
      frame(0, slice.pack("C*"))
    }.join + frame(EOF_BIT)
    received = String.new
    retrbinary_blocks(ChunkedReader.new(frames, 7)) { |data| received << data }
    assert_equal(payload, received)
  end

  def test_retrbinary_blocks_ends_at_eof_descriptor_not_close
    payload = "abc"
    frames = frame(EOR | EOF_BIT, payload) + "trailing garbage"
    received = String.new
    retrbinary_blocks(StringIO.new(frames)) { |data| received << data }
    assert_equal(payload, received)
  end

  def test_retrbinary_blocks_truncated_header
    frames = frame(EOF_BIT, "x")[0, 2]
    assert_raise(Net::FTPProtoError) do
      retrbinary_blocks(StringIO.new(frames)) { }
    end
  end

  def test_retrbinary_blocks_premature_close_without_eof_block
    frames = frame(0, "abc")
    assert_raise(Net::FTPProtoError) do
      retrbinary_blocks(StringIO.new(frames)) { }
    end
  end

  def test_retrbinary_blocks_truncated_payload
    frames = frame(0, "abcdef")[0, 4]
    assert_raise(Net::FTPProtoError) do
      retrbinary_blocks(StringIO.new(frames)) { }
    end
  end

  def test_retrbinary_blocks_error_block
    frames = frame(ERRORS, "abc") + frame(EOF_BIT)
    assert_raise(Net::FTPProtoError) do
      retrbinary_blocks(StringIO.new(frames)) { }
    end
  end

  def test_retrbinary_blocks_restart_marker_is_not_data
    frames = frame(RESTART, "marker") +
             frame(0, "real data") +
             frame(EOF_BIT)
    received = String.new
    retrbinary_blocks(StringIO.new(frames)) { |data| received << data }
    assert_equal("real data", received)
  end

  def test_retrbinary_blocks_progress_excludes_protocol_overhead
    payload = "a" * 100 + "b" * 50
    frames = frame(0, "a" * 100) + frame(EOR | EOF_BIT, "b" * 50)
    progress = 0
    retrbinary_blocks(StringIO.new(frames)) { |data| progress += data.bytesize }
    assert_equal(payload.bytesize, progress)
    assert_operator(frames.bytesize, :>, progress)
  end

  def test_storbinary_blocks_framing
    payload = (0..0xff).map(&:chr).join
    out = StringIO.new
    yielded = String.new
    new_ftp.send(:storbinary_blocks, FakeConn.new(out), StringIO.new(payload), 100) do |buf|
      yielded << buf
    end
    wire = out.string
    blocks = []
    until wire.empty?
      descriptor, count = wire.unpack("Cn")
      blocks << [descriptor, wire.byteslice(3, count)]
      wire = wire.byteslice(3 + count..)
    end
    assert_equal(4, blocks.size)
    assert_equal([0, 0, 0, EOF_BIT], blocks.map(&:first))
    assert_equal([100, 100, 56, 0], blocks.map { |_, data| data.bytesize })
    assert_equal(payload, blocks.map(&:last).join.b)
    assert_equal(payload, yielded.b)
  end

  def test_storbinary_blocks_empty_file
    out = StringIO.new
    new_ftp.send(:storbinary_blocks, FakeConn.new(out), StringIO.new(""), 100)
    assert_equal(frame(EOF_BIT), out.string)
  end

  def test_storbinary_blocks_blocksize_clamped_to_max_count
    payload = "x" * (Net::FTP::MAX_BLOCK_COUNT + 10)
    out = StringIO.new
    new_ftp.send(:storbinary_blocks, FakeConn.new(out), StringIO.new(payload), 100_000)
    descriptor, count = out.string.unpack("Cn")
    assert_equal(0, descriptor)
    assert_equal(Net::FTP::MAX_BLOCK_COUNT, count)
  end

  def test_getbinaryfile_block_mode_progress
    payload = (0..0xff).map(&:chr).join * 3
    frames = frame(0, payload[0, 400]) + frame(EOR | EOF_BIT, payload[400..])
    ftp = new_ftp
    ftp.transfer_mode = :block
    conn = FakeConn.new(StringIO.new(frames))
    ftp.define_singleton_method(:transfercmd) { |*| conn }
    ftp.define_singleton_method(:voidresp) { }
    progress = 0
    received = String.new
    ftp.getbinaryfile("foo", nil, 1024) do |data|
      received << data
      progress += data.bytesize
    end
    assert_equal(payload, received.b)
    assert_equal(payload.bytesize, progress)
  end

  def test_login_sends_mode_command_for_block_mode
    with_control_pair do |ftp, server|
      ftp.transfer_mode = :block
      commands = []
      thread = Thread.new do
        commands << server.gets
        server.print("331 Please specify the password.\r\n")
        commands << server.gets
        server.print("230 Login successful.\r\n")
        commands << server.gets
        server.print("200 Switching to Binary mode.\r\n")
        commands << server.gets
        server.print("200 Using block mode.\r\n")
      end
      ftp.login("user", "pass")
      join_thread(thread)
      assert_equal("USER user\r\n", commands[0])
      assert_equal("PASS pass\r\n", commands[1])
      assert_equal("TYPE I\r\n", commands[2])
      assert_equal("MODE B\r\n", commands[3])
    end
  end

  def test_transfer_mode_set_sends_mode_command_when_logged_in
    with_control_pair do |ftp, server|
      commands = []
      thread = Thread.new do
        run_login_script(server, commands)
        commands << server.gets
        server.print("200 Using block mode.\r\n")
        commands << server.gets
        server.print("200 Using stream mode.\r\n")
      end
      ftp.login("user", "pass")
      ftp.transfer_mode = :block
      ftp.transfer_mode = :stream
      join_thread(thread)
      assert_equal("MODE B\r\n", commands[3])
      assert_equal("MODE S\r\n", commands[4])
    end
  end

  def test_retrbinary_block_mode_with_fake_server
    with_control_pair do |ftp, server|
      data_client, data_server = UNIXSocket.pair
      begin
        conn = Net::FTP::BufferedSocket.new(data_client, read_timeout: 5)
        ftp.define_singleton_method(:transfercmd) { |*| conn }
        ftp.transfer_mode = :block
        payload = (0..0xff).map(&:chr).join * 10
        frames = frame(0, payload[0, 1000]) +
                 frame(RESTART, "marker") +
                 frame(EOR | EOF_BIT, payload[1000..])
        thread = Thread.new do
          frames.scan(/.{1,7}/m) { |s| data_server.write(s) }
          # The data connection stays open: the client must stop at the
          # EOF descriptor, not wait for the TCP close.
          server.print("226 Transfer complete.\r\n")
          server.gets
          server.print("200 NOOP ok.\r\n")
          data_server.close
        end
        received = String.new
        progress = 0
        ftp.retrbinary("RETR foo", 1024) do |data|
          received << data
          progress += data.bytesize
        end
        assert_equal(payload, received)
        assert_equal(payload.bytesize, progress)
        assert_equal("200 NOOP ok.\n", ftp.sendcmd("NOOP"))
        join_thread(thread)
      ensure
        data_server.close unless data_server.closed?
      end
    end
  end

  def test_storbinary_block_mode_with_fake_server
    with_control_pair do |ftp, server|
      data_client, data_server = UNIXSocket.pair
      begin
        conn = Net::FTP::BufferedSocket.new(data_client, read_timeout: 5)
        ftp.define_singleton_method(:transfercmd) { |*| conn }
        ftp.transfer_mode = :block
        payload = (0..0xff).map(&:chr).join * 5
        received = String.new
        descriptors = []
        thread = Thread.new do
          loop do
            header = data_server.read(3)
            descriptor, count = header.unpack("Cn")
            descriptors << descriptor
            data = count > 0 ? data_server.read(count) : ""
            received << data if descriptor & RESTART == 0
            break if descriptor & EOF_BIT != 0
          end
          server.print("226 Transfer complete.\r\n")
          data_server.close
        end
        progress = 0
        ftp.storbinary("STOR foo", StringIO.new(payload), 512) do |buf|
          progress += buf.bytesize
        end
        join_thread(thread)
        assert_equal(payload, received)
        assert_equal(payload.bytesize, progress)
        assert_equal(EOF_BIT, descriptors.last)
        assert(descriptors[0..-2].all? { |d| d == 0 })
      ensure
        data_server.close unless data_server.closed?
      end
    end
  end

  def test_retrlines_forces_stream_mode_during_block_mode_session
    with_control_pair do |ftp, server|
      commands = []
      thread = Thread.new do
        run_login_script(server, commands)
        commands << server.gets # MODE B
        server.print("200 Using block mode.\r\n")
        commands << server.gets # TYPE A
        server.print("200 Switching to ASCII mode.\r\n")
        commands << server.gets # MODE S
        server.print("200 Using stream mode.\r\n")
        server.print("226 Transfer complete.\r\n")
        commands << server.gets # MODE B
        server.print("200 Using block mode.\r\n")
        commands << server.gets # TYPE I
        server.print("200 Switching to Binary mode.\r\n")
      end
      ftp.login("user", "pass")
      ftp.transfer_mode = :block
      conn = FakeConn.new(StringIO.new("line1\r\nline2\r\n"))
      ftp.define_singleton_method(:transfercmd) { |*| conn }
      lines = []
      ftp.retrlines("LIST") { |line, _| lines << line }
      join_thread(thread)
      assert_equal(["line1", "line2"], lines)
      assert_equal("MODE B\r\n", commands[3])
      assert_equal("TYPE A\r\n", commands[4])
      assert_equal("MODE S\r\n", commands[5])
      assert_equal("MODE B\r\n", commands[6])
      assert_equal("TYPE I\r\n", commands[7])
      assert_equal(Net::FTP::BLOCK_MODE, ftp.transfer_mode)
    end
  end

  private

  def with_control_pair
    client, server = UNIXSocket.pair
    ftp = Net::FTP.new
    ftp.send(:set_socket, Net::FTP::BufferedSocket.new(client, read_timeout: 5), false)
    yield ftp, server
  ensure
    ftp.close if ftp && !ftp.closed?
    server.close if server && !server.closed?
  end

  # Answers the USER/PASS/TYPE I commands sent by Net::FTP#login.
  def run_login_script(server, commands)
    commands << server.gets
    server.print("331 Please specify the password.\r\n")
    commands << server.gets
    server.print("230 Login successful.\r\n")
    commands << server.gets
    server.print("200 Switching to Binary mode.\r\n")
  end

  def join_thread(thread)
    unless thread.join(10)
      thread.kill
      flunk("server thread did not finish")
    end
    thread.value
  end
end
