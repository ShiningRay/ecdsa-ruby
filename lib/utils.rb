module Utils
  extend self
  def hex2bytes(hexstr)
    hexstr = hexstr[2..-1] if hexstr.start_with?("0x")
    hexstr.scan(/../).map(&:hex).pack("C*")
  end

  def bytes2hex(bytes, prefix: "0x")
    h = bytes.unpack("H*").first
    "#{prefix}#{h}"
  end

  def self.to_array(msg, enc)
    if msg.is_a?(Array)
      return msg.dup
    end

    return [] if msg.nil?

    res = []
    if !msg.is_a?(String)
      msg.length.times do |i|
        res[i] = msg[i] & 0
      end
    elsif enc == "hex"
      msg.gsub!(/[^a-z0-9]+/i, "")
      msg = "0" + msg if msg.length.odd?
      (0...msg.length).step(2) do |i|
        res << msg[i, 2].to_i(16)
      end
    else
      msg.chars.each do |c|
        code = c.ord
        hi = code >> 8
        lo = code & 0xff
        if hi > 0
          res << hi << lo
        else
          res << lo
        end
      end
    end
    res
  end

  def self.zero2(word)
    if word.length == 1
      "0" + word
    else
      word
    end
  end

  def self.to_hex(msg)
    res = ""
    msg.each do |m|
      res += zero2(m.to_s(16))
    end
    res
  end

  def self.encode(arr, enc)
    if enc == "hex"
      to_hex(arr)
    else
      arr
    end
  end
end
