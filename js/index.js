/**
 * @file index.js
 * @author sw
 * @license MIT
 *
 * HTML UI for index.html/hotp.js.
 */
const onDocumentLoaded = function() {
  const secret_input = document.getElementById("otp-secret-base32");
  const token_period_input = document.getElementById("otp-period");
  const digits_input = document.getElementById("otp-num-digits");
  const otp_input = document.getElementById("otp-expected");
  const time_left_input = document.getElementById("otp-timeleft");
  const timestamp_input = document.getElementById("otp-current-timestamp");
  const counter_input = document.getElementById("otp-counter");
  const padded_counter_input = document.getElementById("otp-counter-padded");
  const secret_bytes_input = document.getElementById("otp-secret-bytes");
  const hmac_input = document.getElementById("otp-hmac");
  const error_message_span = document.getElementById("otp-error-message");
  const randomize_secret_button = document.getElementById("randomize-secret");

  const bytes2str = (arr)=>{
    return arr.map((x)=>x.toString(16).padStart(2, "0")).join("|");
  };

  const update = ()=>{
    try {
      // Fetch current arguments.
      const args = {
        secret_base32: secret_input.value.trim().toUpperCase(),
        unix_timestamp: Math.round(Date.now() / 1000),
        token_period_s: Number.parseInt(token_period_input.value),
        num_htop_digits: Number.parseInt(digits_input.value)
      };

      // Calculate and log.
      const data = HOTP.calculate_otp_data(args);
      const secs = HOTP.timer(args);
      //console.log("Input arguments:", args);
      //console.log("Results:", data);

      // Assign UI element data.
      error_message_span.textContent = "";
      timestamp_input.value = args.unix_timestamp;
      time_left_input.value = secs;
      otp_input.value = data.expected_otp.toString(10).padStart(args.num_htop_digits, "0");
      counter_input.value = data.counter_value;
      padded_counter_input.value = bytes2str(data.counter_bytes);
      secret_bytes_input.value = bytes2str(data.secret_bytes);
      hmac_input.value = bytes2str(data.hmac)

      // Adjust secret upper-case values if needed.
      if(secret_input.value != args.secret_base32) {
        secret_input.value = args.secret_base32;
      }
    } catch(ex) {
      error_message_span.textContent = ex.message;
      otp_input.value = "";
      counter_input.value = "";
      padded_counter_input.value = "";
      secret_bytes_input.value = "";
      hmac_input.value = "";
    }

    // Show/hide error message block.
    if(error_message_span.textContent == "") {
      error_message_span.classList.add('hidden');
    } else {
      error_message_span.textContent = "Error: " + error_message_span.textContent;
      error_message_span.classList.remove('hidden');
    }

  };

  // Events
  secret_input.addEventListener('change', update);
  token_period_input.addEventListener('change', update);
  digits_input.addEventListener('change', update);
  digits_input.addEventListener('change', update);
  randomize_secret_button.addEventListener('click', ()=>{ secret_input.value = HOTP.random_secret(); });
  window.setInterval(update, 1000);

  // Initial update
  update();
}
