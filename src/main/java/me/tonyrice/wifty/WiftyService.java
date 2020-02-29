package me.tonyrice.wifty;

import java.io.Console;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystem;
import io.vertx.core.json.JsonObject;

public class WiftyService extends AbstractVerticle {

  final private String XPATH_INPUT_SUBMIT = "//input[@type='submit']";

  public static void main(String[] args) {
    Vertx.vertx().deployVerticle(new WiftyService());
  }

  private WorkerExecutor cliExec = null;
  private WorkerExecutor browserExec = null;

  @Override
  public void start() {
    System.out.println("Starting Wifty (Wyze IFTTT Synchronization Service)");

    cliExec = vertx.createSharedWorkerExecutor("cli-pool", 1, 24, TimeUnit.HOURS);
    browserExec = vertx.createSharedWorkerExecutor("browser-pool", 1, 5, TimeUnit.MINUTES);

    vertx.runOnContext(h -> {
      getEncryptedData(res -> {
        if (res.failed()) {
          System.out.println("Could not start Wifty. Failed to decode secure data!");
          vertx.close();
          return;
        }

        vertx.setPeriodic(TimeUnit.MINUTES.toMillis(15), act -> {
          syncIftttWyzeConnection(res.result(), sRes -> {
            if (sRes.failed()) {
              sRes.cause().printStackTrace();
            }
          });
        });
        System.out.println("WIFTY has started. Your IFTTT to Wyze connection should stay active :)");
      });
    });
  }

  @Override
  public void stop() throws Exception {
    System.out.println("Wifty is shutting down");
  }

  private void syncIftttWyzeConnection(JsonObject secureData, Handler<AsyncResult<Void>> handler) {
    browserExec.executeBlocking(fut -> {
      ChromeOptions options = new ChromeOptions().addArguments("--headless", "--disable-gpu",
          "--window-size=1920,1200");

      WebDriver driver = new ChromeDriver(options);

      try {

        System.out.println("Opening IFTTT...");

        // 1. Open IFTTT
        driver.get("https://ifttt.com/");

        try {
          // Are we logged in? Probably not. (Not supported yet.)
          WebElement elm = driver.findElement(By.cssSelector("[class='profile-avatar-container']"));
          if (!elm.isDisplayed()) {
            throw new WebDriverException("Profile not displayed.");
          }
        } catch (WebDriverException e) {
          try {

            System.out.println("Logging into your IFTTT account...");

            // Go to the login page.
            driver.get("https://ifttt.com/login?wp_=1");

            // Login.
            driver.findElement(By.cssSelector("#user_username")).sendKeys(secureData.getString("ifttt_email"));
            driver.findElement(By.cssSelector("#user_password")).sendKeys(secureData.getString("ifttt_password"));
            driver.findElement(By.xpath(XPATH_INPUT_SUBMIT)).click();

            // is 2fa enabled?
            try {
              WebElement tfa = driver.findElement(By.cssSelector("#user_tfa_code"));
              if (tfa != null && tfa.isDisplayed()) {
                tfa.sendKeys(secureData.getString("ifttt_2fa"));
                driver.findElement(By.xpath(XPATH_INPUT_SUBMIT)).click();
              }
            } catch (WebDriverException ignored) {
            }
            System.out.println("Logged into your IFTTT account...");

          } catch (WebDriverException noe3) {
            // We couldn't login!
            fut.fail(e);
            return;
          }
        }

        try {

          System.out.println("Validating if any Wyze devices with motion support are available...");

          driver.navigate().to("https://ifttt.com/create/if-wyzecam?sid=6");
          driver.navigate().to("https://ifttt.com/create/if-motion-is-detected?sid=7");

          WebElement list = driver.findElement(By.cssSelector("[name=\"fields[serialize_device_info]\"]"));
          List<WebElement> elms = list.findElements(By.cssSelector("option"));

          if (elms.size() > 1) {
            System.out.println(elms.size() + " Wyze device(s) " + (elms.size() == 1 ? "is" : "are") + " available...");
            fut.complete();
            return;
          }
          System.out.println("No Wyze Cams are available...");

        } catch (WebDriverException e) {
          System.out.println("Failed to detect any Wyze devices...");
        }

        // Authenticate with Wyze, and Login!
        try {

          System.out.println("Reauthorization Wyze <> IFTTT connection...");

          driver.navigate().to("https://ifttt.com/wyzecam/settings");
          driver.navigate().to("https://ifttt.com/wyzecam/settings/connect");
          driver.findElement(By.cssSelector("#Username")).sendKeys(secureData.getString("wyze_email"));
          driver.findElement(By.cssSelector("#Password")).sendKeys(secureData.getString("wyze_password"));
          driver.findElement(By.xpath(XPATH_INPUT_SUBMIT)).click();
          driver.findElement(By.xpath(XPATH_INPUT_SUBMIT)).click();
        } catch (WebDriverException e) {
          System.out.println("Failed to reauthorize Wyze <> IFTTT connection...");
          fut.fail(e);
          return;
        }

        System.out.println("Completed reauthorization of Wyze <> IFTTT connection...");

        fut.complete();
      } catch (Exception e) {
        fut.fail(e);
      } finally {
        driver.quit();
      }
    }, handler);

  }

  private SecretKeyFactory encKeyFactory = null;
  private SecureRandom random = null;

  private void cryptInitialized() throws Exception {
    if (encKeyFactory == null) {
      try {
        encKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        random = SecureRandom.getInstanceStrong();
      } catch (NoSuchAlgorithmException e) {
        throw new Exception("Could not initialize SecretKeyFactory and SecureRandom!");
      }
    }
  }

  public Buffer decrypt(Buffer toDecrypt, String secret) throws Exception {
    cryptInitialized();

    byte[] salt = toDecrypt.getBytes(0, 16);
    byte[] iv = toDecrypt.getBytes(16, 32);

    IvParameterSpec ivspec = new IvParameterSpec(iv);

    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 65536, 256);
    SecretKey tmp = factory.generateSecret(spec);
    SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
    return Buffer.buffer(cipher.doFinal(toDecrypt.getBytes(32, toDecrypt.length())));
  }

  public Buffer encrypt(Buffer toEncrypt, String secret) throws Exception {
    cryptInitialized();

    byte[] iv = new byte[16];
    random.nextBytes(iv);

    IvParameterSpec ivspec = new IvParameterSpec(iv);

    byte[] salt = new byte[16];
    random.nextBytes(salt);
    KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 65536, 256);
    SecretKey tmp = encKeyFactory.generateSecret(spec);
    SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

    Buffer encrypted = Buffer.buffer();
    encrypted.appendBytes(salt);
    encrypted.appendBytes(iv);
    encrypted.appendBytes(cipher.doFinal(toEncrypt.getBytes()));
    return encrypted;
  }

  private void getEncryptedData(Handler<AsyncResult<JsonObject>> handler) {

    cliExec.executeBlocking(fut -> {
      String secureData = "wifty.json.enc";

      // Obtaining a reference to the console.
      Console con = System.console();

      // Checking If there is no console available, then exit.
      if (con == null) {
        handler.handle(Future.failedFuture("No console available."));
        System.exit(0);
        return;
      }

      FileSystem fs = vertx.fileSystem();

      if (fs.existsBlocking(secureData)) {

        System.out.println("\"" + secureData + "\" has been found. Attempting to decrypt...");

        System.out.println("Please your encryption password: ");

        String encPass = String.valueOf(con.readPassword());

        Buffer data = fs.readFileBlocking(secureData);

        try {

          Buffer dec = decrypt(data, encPass);

          if (dec == null) {
            handler.handle(Future.failedFuture("Failed to decrypt."));
            return;
          }

          fut.complete(new JsonObject(dec));
        } catch (Exception e) {
          e.printStackTrace();
          fut.fail(e);
          return;
        }

      } else {

        System.out.println("\"" + secureData + "\" was not found. Creating now...");

        JsonObject data = new JsonObject();

        String encFinalPass = null;

        while (encFinalPass == null) {
          System.out.println("Please enter an encryption password: ");
          String encPass = String.valueOf(con.readPassword());
          System.out.println("Please verify your encryption password: ");
          String encPass2 = String.valueOf(con.readPassword());

          if (!encPass.equals(encPass2)) {
            System.out.println("Passwords do not match. Please try again");
            continue;
          }
          encFinalPass = encPass;
        }

        // to read password and then display it
        System.out.println("Enter your IFTTT email: ");

        String email = con.readLine();
        // Password save char type

        System.out.println("Enter your IFTTT password: ");
        char[] ch = con.readPassword();
        String pass = String.valueOf(ch);

        data.put("ifttt_email", email);
        data.put("ifttt_password", pass);

        System.out.println("Enter your IFTTT 2fa recovery token if any: ");
        String tfaPass = String.valueOf(con.readPassword());

        data.put("ifttt_tfa", tfaPass);

        // to read password and then display it
        System.out.println("Enter your Wyze email: ");

        String wyzeEmail = con.readLine();
        // Password save char type

        System.out.println("Enter your Wyze password: ");
        String wyzePass = String.valueOf(con.readPassword());

        data.put("wyze_email", wyzeEmail);
        data.put("wyze_password", wyzePass);

        try {

          Buffer encData = encrypt(Buffer.buffer(data.encodePrettily()), encFinalPass);

          fs.writeFileBlocking(secureData, encData);
          System.out.println("\"" + secureData + "\" was created.");

          fut.complete(data);
        } catch (Exception e) {
          fut.fail(e);
          return;
        }
      }

      fut.fail("Could not retrieve data!");

    }, handler);
  }
}
