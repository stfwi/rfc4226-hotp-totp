/**
 * @file hotp.js
 * @author sw
 * @license MIT
 *
 * HOTP/TOTP ("Hashed One-Time Password"/"Timed One-Time Password")
 * calculation according to RFC4226.
 */
const HOTP = {

  /**
   * HOTP/TOTP calculation with intermediate results.
   * @param {object} args
   * @returns {object}
   */
  calculate_otp_data: function(args) {
    /**
     * Returns a (big endian ordered) representation of
     * a given BASE32 encoded byte stream.
     * @param {string} b32
     * @returns array
     */
    const from_base32 = function(b32) {
      const buf = b32.replace(/=+$/,"").split("").map(c=>"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c));
      const inval_pos = buf.indexOf(-1);
      if(inval_pos >= 0) throw new Error("Invalid base32 character '" + b32[inval_pos] + "' at position " + (inval_pos+1));
      const out_bytes = [];
      let buf_bits = 0;
      let buf_word = 0;
      while(buf.length > 0) {
        buf_bits += 5;
        buf_word = (buf_word<<5) | buf.shift();
        if(buf_bits >= 8) {
          out_bytes.push((buf_word >>> (buf_bits-8)) & 0xff);
          buf_bits -= 8;
        }
      }
      return out_bytes;
    }

    /**
     * Calculates a uint64 big endian chunked in bytes from a
     * numeric counter value.
     * @param {number} numeric_counter
     * @returns {array}
     */
    const padded_counter = function(numeric_counter) {
      return numeric_counter.toString(16).padStart(16, "0").match(/.{1,2}/g).map(s=>Number.parseInt(s,16));
    }

    /**
     * Calculates a SHA-1 HMAC from a given secret key (byte array)
     * and a padded counter (64bit as big endian byte array). The
     * HMAC is by definition a 160-bit value (20 byte array).
     *
     * Covers RFC4226 instruction step 1: HS = HMAC-SHA-1(K,C)
     *
     * @param {array} secret
     * @param {array} counter
     * @returns {array}
     */
    const get_hmac = function(secret, counter) {
      if((window.jsSHA !== undefined) || ((!!globalThis) && (globalThis.jsSHA))) {
        // SHA1 using jsSHA
        const hash = new jsSHA("SHA-1", "UINT8ARRAY");
        hash.setHMACKey(Uint8Array.from(secret), "UINT8ARRAY");
        hash.update(Uint8Array.from(counter));
        return Array.from(hash.getHMAC("UINT8ARRAY"));
      } else {
        throw new Error("No crypto/SHA1 calculator available");
      }
    }

    /**
     * Dynamically truncates a HMAC byte array to a
     * 4-byte array. The truncation rules of RFC4226
     * are applied. Do not search for a special logic
     * behind the algorithm, it is simply implemented
     * as specified, we pick a series of 4 bytes
     * depending on the offset in last byte 19. The
     * bytes are interpreted as 32bit signed number,
     * where the last bit is masked out to make it
     * guaranteed unsigned. Lastly, using decimal
     * modulo, the number of digits is determined from
     * that.
     *
     * Covers RFC4226 instruction step 2/3:
     *    | Sbits = DT(HS)
     *    | Let Snum  = StToNum(Sbits)
     *    | Return D = Snum mod 10^Digit
     *
     * @param {array} hmac
     * @param {number} num_digits
     * @returns {array}
     */
    const get_truncated = function(hmac, num_digits) {
      if((!hmac) || (hmac.length != 20)) {
        throw new Error("HMAC values must be 20 bytes (160-bit) long.");
      }
      if((!num_digits) || (num_digits < 6) || (num_digits > 10)) {
        throw new Error("HOTP truncation digits implausible.");
      }
      const offset = hmac[19] & 0xf;
      const picked = ((hmac[offset+0] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) | ((hmac[offset+2] & 0xff) << 8) | ((hmac[offset+3] & 0xff));
      const modulo = 10 ** num_digits;
      return picked % modulo;
    }

    /**
     * Actual calculation sequence using the functions above.
     * @param {object} args
     * @returns {object}
     */
    const calc = function(args) {
      if(typeof(args) !== "object") {
        throw new Error("No named argument object given.");
      } else if((args.htop_counter===undefined) === (args.unix_timestamp===undefined)) {
        throw new Error("One of a HOTP counter or a unix timestamp (for TOTP) has to be specified, but not both.");
      } else if((args.unix_timestamp!==undefined) && (args.token_period_s===undefined)) {
        throw new Error("TOTP requires specifying a refresh time in seconds.");
      }

      const secret = from_base32(args.secret_base32);
      const counter_value = (args.htop_counter!==undefined) ? (args.htop_counter) : Math.floor(args.unix_timestamp / args.token_period_s);
      const hotp_counter = padded_counter(counter_value);
      const hmac = get_hmac(secret, hotp_counter);
      const hmac_truncated = get_truncated(hmac, args.num_htop_digits);

      return {
        secret_bytes: secret,
        counter_value: counter_value,
        counter_bytes: hotp_counter,
        hmac: hmac,
        expected_otp: hmac_truncated,
      };
    }

    return calc(args);
  },

  /**
   * HOTP/TOTP calculation, returns the expected OTP.
   * @param {object} args
   * @returns {number}
   */
  calculate: function(args) {
    return HOTP.calculate_otp_data(args).expected_otp;
  },

  /**
   * Returns how much time is left until the current
   * TOTP token is obsolete and a new token active.
   * Use this for UI count-down timer rendering.
   * @param {object} args
   * @returns {number}
   */
  timer: function(args) {
    if(!args.unix_timestamp) return 0;
    if(!args.token_period_s) throw new Error("HOTP refresh time unspecified.");
    const counter_value = Math.floor(args.unix_timestamp / args.token_period_s);
    const seconds_left = args.token_period_s - (args.unix_timestamp - (counter_value * args.token_period_s));
    return Math.max(Math.min(seconds_left, args.token_period_s), 0);
  },

  /**
   * Generates a random BASE32 secret (6 to 16 characters).
   * @returns {string}
   */
  random_secret() {
    const base32_mapping = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const num_chars = Math.ceil(3 + (Math.random() * 5)) * 2;
    const bytes = [];
    for(let i = num_chars; i > 0; --i) { bytes.push(Math.floor(Math.random() * 256) & 0x1f); }
    return bytes.map(b=>base32_mapping[b]).join("");
  }

};

Object.freeze(HOTP);
