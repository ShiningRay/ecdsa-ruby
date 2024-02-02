require 'digest'
require_relative './hmac_drbg'

module EllipticCurve
    module Ecdsa
        def self.sign(message, privateKey, hashfunc=nil)
            if hashfunc.nil? then hashfunc = lambda{ |x| Digest::SHA256.digest(x) } end
            byteMessage = hashfunc.call(message)
            numberMessage = Utils::Binary.numberFromByteString(byteMessage)
            curve = privateKey.curve
            n_bytes = curve.n.bit_length / 8
            puts n_bytes
            a=Utils::Binary.hex2bytes(privateKey.toString.rjust(n_bytes*2, '0'))
            puts a.size
            drbg = DRBG::HMAC.new(a, 256, byteMessage)
            r, s, randSignPoint = 0, 0, nil
            while r == 0 or s == 0
                randNum = drbg.generate(n_bytes)
                randSignPoint = Math.multiply(curve.g, randNum, curve.n, curve.a, curve.p)
                r = randSignPoint.x % curve.n
                s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.n))) % curve.n
            end
            recoveryId = randSignPoint.y & 1
            if randSignPoint.y > curve.n
                recoveryId += 2
            end
            return Signature.new(r, s, recoveryId)
        end

        def self.verify(message, signature, publicKey, hashfunc=nil)
            if hashfunc.nil? then hashfunc = lambda{ |x| Digest::SHA256.digest(x) } end
            byteMessage = hashfunc.call(message)
            numberMessage = Utils::Binary.numberFromByteString(byteMessage)

            curve = publicKey.curve
            r = signature.r
            s = signature.s
            if not (1 <= r and r <= curve.n - 1)
                return false
            end
            if not (1 <= s and s <= curve.n - 1)
                return false
            end
            inv = Math.inv(s, curve.n)
            u1 = Math.multiply(curve.g, (numberMessage * inv) % curve.n, curve.n, curve.a, curve.p)
            u2 = Math.multiply(publicKey.point, (r * inv) % curve.n, curve.n, curve.a, curve.p)
            v = Math.add(u1, u2, curve.a, curve.p)
            if v.isAtInfinity
                return false
            end
            return v.x % curve.n == r
        end
    end
end
