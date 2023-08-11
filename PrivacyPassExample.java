import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.net.HttpURLConnection;
import java.net.URI;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

class PrivacyPassExample {
  static {
    System.loadLibrary("blind_rsa");
  }

  // Token request media type
  private static final String requestMediaType = "message/token-request";

  // Hard-coded issuer URL
  private static final String issuerUrl = "http://issuer.example:4567/token-request";

  // Hard-coded issuer directory URL
  private static final String issuerDirectoryUrl = "http://issuer.example:4567/.well-known/private-token-issuer-directory";

  // Allocators
  private native long brsa_context_new();
  private native long brsa_secret_key_new();
  private native long brsa_public_key_new();
  private native long brsa_blind_message_new();
  private native long brsa_blinding_secret_new();
  private native long brsa_blind_signature_new();
  private native long brsa_signature_new();

  // Decoding functions
  private native int brsa_publickey_import_spki(long context_ptr, long public_key_ptr, byte[] spki);
  private native int brsa_blind_signature_import(long context_ptr, long blind_sig_ptr, byte[] encoded_blind_sig);

  // Decallocators
  private native void brsa_context_free(long context_ptr);
  private native void brsa_secret_key_free(long secret_key_ptr);
  private native void brsa_public_key_free(long public_key_ptr);
  private native void brsa_blind_message_free(long blind_message_ptr);
  private native void brsa_blinding_secret_free(long blinding_secret_ptr);
  private native void brsa_blind_signature_free(long blind_signature_ptr);
  private native void brsa_signature_free(long sig_ptr);

  // Accessors
  private native byte[] brsa_blind_message_copy(long blind_msg_ptr);
  private native byte[] brsa_signature_copy(long sig_ptr);

  // Protocol functions
  private native void brsa_context_init(long context_ptr);
  private native int brsa_keygen(long secret_key_ptr, long public_key_ptr, int size);
  private native int brsa_blind_wrapper(long ctx_ptr, long blind_msg_ptr, long blinding_secret_ptr, long public_key_ptr, byte[] msg);
  private native int brsa_blind_sign_wrapper(long ctx_ptr, long blind_sig_ptr, long secret_key_ptr, long blind_msg_ptr);
  private native int brsa_finalize_wrapper(long ctx_ptr, long sig_ptr, long blind_sig_ptr, long blinding_secret_ptr, long public_key_ptr, byte []msg);
  private native int brsa_verify(long ctx_ptr, long sig_ptr, long public_key_ptr, byte []msg);

  private static String readAll(Reader rd) throws IOException {
    StringBuilder sb = new StringBuilder();
    int cp;
    while ((cp = rd.read()) != -1) {
      sb.append((char) cp);
    }
    return sb.toString();
  }

  private static JSONObject readJsonFromUrl(String url) throws IOException, JSONException {
    InputStream inputStream = new URL(url).openStream();
    try {
      BufferedReader rd = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("UTF-8")));
      String jsonText = readAll(rd);
      JSONObject json = new JSONObject(jsonText);
      return json;
    } finally {
      inputStream.close();
    }
  }

  public static byte[] inputStreamToByte(InputStream is) {
    try {
        ByteArrayOutputStream bytestream = new ByteArrayOutputStream();
        int octet;
        while ((octet = is.read()) != -1) {
            bytestream.write(octet);
        }
        byte imgdata[] = bytestream.toByteArray();
        bytestream.close();
        return imgdata;
    } catch (Exception e) {
        e.printStackTrace();
    }

    return null;
  }

  public void runExample() throws Exception {
    PrivacyPassExample shim = new PrivacyPassExample();

    long context_ptr = shim.brsa_context_new();
    long secret_key_ptr = shim.brsa_secret_key_new();
    long public_key_ptr = shim.brsa_public_key_new();
    int result = brsa_keygen(secret_key_ptr, public_key_ptr, 2048);

    shim.brsa_context_init(context_ptr);

    byte []msg = new byte[5];
    msg[0] = (byte)1;
    msg[1] = (byte)2;
    msg[2] = (byte)3;
    msg[3] = (byte)4;
    msg[4] = (byte)5;
    long blind_msg_ptr = shim.brsa_blind_message_new();
    long blinding_secret_ptr = shim.brsa_blinding_secret_new();
    result = shim.brsa_blind_wrapper(context_ptr, blind_msg_ptr, blinding_secret_ptr, public_key_ptr, msg);
    
    long blind_sig_ptr = shim.brsa_blind_signature_new();
    result = shim.brsa_blind_sign_wrapper(context_ptr, blind_sig_ptr, secret_key_ptr, blind_msg_ptr);

    long sig_ptr = shim.brsa_signature_new();
    result = shim.brsa_finalize_wrapper(context_ptr, sig_ptr, blind_sig_ptr, blinding_secret_ptr, public_key_ptr, msg);
    result = shim.brsa_verify(context_ptr, sig_ptr, public_key_ptr, msg);

    if (result != 0) {
      throw new Exception("example failed");
    }

    shim.brsa_context_free(context_ptr);
    shim.brsa_secret_key_free(secret_key_ptr);
    shim.brsa_public_key_free(public_key_ptr);
    shim.brsa_blind_message_free(blind_msg_ptr);
    shim.brsa_blinding_secret_free(blinding_secret_ptr);
    shim.brsa_blind_signature_free(blind_sig_ptr);
    shim.brsa_signature_free(sig_ptr);
  }

  public static void main(String[] args) throws Exception {
    PrivacyPassExample shim = new PrivacyPassExample();

    // Run a local end-to-end example
    shim.runExample();

    try {
      // Fetch the issuer's directory and parse out the first "token-keys" value
      JSONObject directory = shim.readJsonFromUrl(issuerDirectoryUrl);
      JSONArray tokenKeys = directory.getJSONArray("token-keys");
      JSONObject tokenKey = tokenKeys.getJSONObject(0);
      String encodedTokenKey = tokenKey.getString("token-key");

      byte[] rawKey = Base64.getUrlDecoder().decode(encodedTokenKey);

      long context_ptr = shim.brsa_context_new();
      shim.brsa_context_init(context_ptr);

      // Import the public key from the issuer
      long public_key_ptr = shim.brsa_public_key_new();
      int result = shim.brsa_publickey_import_spki(context_ptr, public_key_ptr, rawKey);
      if (result != 0) {
        throw new Exception("brsa_publickey_import_spki failed");
      }

      // Create the message to be signed (token_input). In Privacy Pass, this is as specified here:
      //   https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-client-to-issuer-request-2
      // In this example, we just pass in an arbitrary hard-coded array of 5 bytes.
      byte []token_input = {0, 1, 2, 3, 4};
      long blind_msg_ptr = shim.brsa_blind_message_new();
      long blinding_secret_ptr = shim.brsa_blinding_secret_new();
      result = shim.brsa_blind_wrapper(context_ptr, blind_msg_ptr, blinding_secret_ptr, public_key_ptr, token_input);
      if (result != 0) {
        throw new Exception("brsa_blind_wrapper failed");
      }

      // Construct a TokenRequest. Note that this does not compute the truncated key ID correctly.
      // The key ID is computed as specified here: 
      //   https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-protocol.html#name-issuer-configuration-2
      byte[] blindMessage = shim.brsa_blind_message_copy(blind_msg_ptr);
      byte[] tokenRequest = new byte[259];
      tokenRequest[0] = 0x00;
      tokenRequest[1] = 0x02; // token_type = 0x0002
      tokenRequest[3] = 0x00;
      for (int i = 0; i < blindMessage.length; i++) {
        tokenRequest[i+3] = blindMessage[i];
      }

      // Send the TokenRequest to the issuer and read the response
      URL tokenRequestURI = new URI(issuerUrl).toURL();
      HttpURLConnection connection = (HttpURLConnection)tokenRequestURI.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", requestMediaType);

      connection.setDoOutput(true);
      OutputStream outputWriter = connection.getOutputStream();
      outputWriter.write(tokenRequest);
      outputWriter.flush();
      outputWriter.close();

      byte[] data = inputStreamToByte(connection.getInputStream());
      connection.disconnect();

      long sig_ptr = shim.brsa_signature_new();
      long blind_sig_ptr = shim.brsa_blind_signature_new();

      // Parse the issuer response
      result = shim.brsa_blind_signature_import(context_ptr, blind_sig_ptr, data);
      if (result != 0) {
        throw new Exception("brsa_blind_signature_import failed");
      }

      // Finalize the result to create a signature (the Token.authenticator value)
      result = shim.brsa_finalize_wrapper(context_ptr, sig_ptr, blind_sig_ptr, blinding_secret_ptr, public_key_ptr, token_input);
      if (result != 0) {
        throw new Exception("brsa_finalize_wrapper failed");
      }

      // TODO: construct a Token from the signature and token_input as specified here:
      //    https://ietf-wg-privacypass.github.io/base-drafts/draft-ietf-privacypass-auth-scheme.html#name-token-redemption

      // Free all memory
      shim.brsa_context_free(context_ptr);
      shim.brsa_public_key_free(public_key_ptr);
      shim.brsa_blind_message_free(blind_msg_ptr);
      shim.brsa_blinding_secret_free(blinding_secret_ptr);
      shim.brsa_blind_signature_free(blind_sig_ptr);
      shim.brsa_signature_free(sig_ptr);
    } catch (JSONException e) {
      System.err.println(e);
      System.exit(-1);
    }
  }
}