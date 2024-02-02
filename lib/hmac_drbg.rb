require "openssl"
require "utils"
require "digest"
require_relative './utils'

class HmacDRBG
  attr_accessor :K, :V, :hash, :predResist, :outLen, :minEntropy, :_reseed, :reseedInterval

  def initialize(options)
    self.hash = OpenSSL::Digest.new(options[:hash])
    self.predResist = !!options[:predResist]
    self.outLen = self.hash.digest_length
    self.minEntropy = options[:minEntropy] || self.hash.digest_length

    self._reseed = nil
    self.reseedInterval = nil
    self.K = nil
    self.V = nil

    entropy = Utils.to_array(options[:entropy], options[:entropyEnc] || "hex")
    nonce = Utils.to_array(options[:nonce], options[:nonceEnc] || "hex")
    pers = Utils.to_array(options[:pers], options[:persEnc] || "hex")

    if entropy.length < (self.minEntropy / 8)
      raise ArgumentError, "Not enough entropy. Minimum is: #{self.minEntropy} bits"
    end

    seed = entropy + nonce + pers
    self.K = Array.new(self.outLen / 8)
    self.V = Array.new(self.outLen / 8)
    self.V.length.times do |i|
      self.K[i] = 0x00
      self.V[i] = 0x01
    end
    self._update(seed)
    self._reseed = 1
    self.reseedInterval = 0x1000000000000 # 2^48
  end

  def _hmac
    OpenSSL::HMAC.new(self.K.pack("C*"), self.hash)
  end

  def _update(seed)
    kmac = _hmac.update(self.V.pack("C*")).update([0x00].pack("C*"))
    kmac = kmac.update(seed.pack("C*")) if seed
    self.K = kmac.digest.unpack("C*")
    self.V = _hmac.update(self.V.pack("C*")).digest.unpack("C*")
    if seed
      self.K = _hmac.update(self.V.pack("C*")).update([0x01].pack("C*")).update(seed.pack("C*")).digest.unpack("C*")
      self.V = _hmac.update(self.V.pack("C*")).digest.unpack("C*")
    end
  end

  def reseed(entropy, entropyEnc, add = nil, addEnc = nil)
    entropy = Utils.to_array(entropy, entropyEnc)
    add = Utils.to_array(add, addEnc)

    if entropy.length < (self.minEntropy / 8)
      raise ArgumentError, "Not enough entropy. Minimum is: #{self.minEntropy} bits"
    end

    self._update(entropy + (add || []))
    self._reseed = 1
  end

  def generate(len, enc = nil, add = nil, addEnc = nil)
    raise "Reseed is required" if self._reseed > self.reseedInterval

    add = Utils.to_array(add, addEnc || "hex") if add
    self._update(add)

    temp = []
    while temp.length < len
      self.V = _hmac.update(self.V.pack("C*")).digest.unpack("C*")
      temp += self.V
    end

    res = temp[0...len]
    self._update(add)
    self._reseed += 1
    Utils.encode(res, enc)
  end
end
