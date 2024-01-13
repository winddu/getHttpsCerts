package com.kshow;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.alidns.model.v20150109.AddDomainRecordRequest;
import com.aliyuncs.alidns.model.v20150109.AddDomainRecordResponse;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;

public class Main {
    String configFile = "conf.properties";
    String jarDir = System.getProperty("user.dir") + File.separator;
    String logDir = jarDir + "logs" + File.separator;
    String sslDir = jarDir + "SSLs" + File.separator;
    String regionId = "cn-hangzhou";
    String accessKeyId = "";
    String accessKeySecret = "";
    String certDomain = "";
    // 要动态解析的子域名列表
    String[] domainArray = null;
    String nginxPath = "";
    // File name of the User Key Pair
    private static final String USER_KEY_FILENAME = "user.key";

    // File name of the Domain Key Pair
    private static final String DOMAIN_KEY_FILENAME = "domain.key";

    // File name of the CSR
    // private static final File DOMAIN_CSR_FILE = new File("domain.csr");

    // File name of the signed certificate
    private static final String DOMAIN_CHAIN_FILENAME = "domain-chain.pem";

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;
    DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss");

    public static void main(String[] args) {
        Main main = new Main();
        main.start();
    }

    private void start() {
        mkDir(logDir);
        mkDir(sslDir);
        log("程序启动");
        log("Made By wINDDu 2024....Contact:duwei#jieji.vip");
        Properties properties = this.getProperties();
        if (properties == null) {
            return;
        }
        accessKeyId = properties.getProperty("accessKeyId");
        accessKeySecret = properties.getProperty("accessKeySecret");
        certDomain = properties.getProperty("certDomain");
        domainArray = certDomain.split(",");
        nginxPath = properties.getProperty("nginxPath");

        if (accessKeyId.isEmpty() || accessKeySecret.isEmpty() || certDomain.isEmpty()) {
            log("参数不能为空");
            exitAPP();
        } else {
            Security.addProvider(new BouncyCastleProvider());
            for (String domain : domainArray) {
                getSSL(domain);
            }
            if (!nginxPath.isEmpty()) {
                //调用nginx重新加载
                reloadNginx();
            }
        }
    }

    private void reloadNginx() {
        if (judgeOs()) {
            reloadWindowNginx();
        } else {
            reloadLinuxNginx();
        }
    }

    private void mkDir(String dir) {
        File f = new File(dir);
        if (!f.exists()) {
            if (!f.mkdirs()) {
                log("严重:" + dir + "文件夹创建失败!请检查是否有权限创建" + dir + "文件夹!");
                exitAPP();
            }
        } else if (f.isFile()) {
            log("严重:" + dir + "应该是文件夹，但现在被文件占用，请手动删除或移动此文件后再重试!");
            exitAPP();
        }
    }

    private KeyPair loadOrCreateUserKeyPair(String domain) throws IOException {
        File USER_KEY_FILE = new File(sslDir + domain + File.separator + USER_KEY_FILENAME);
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    private KeyPair loadOrCreateDomainKeyPair(String domain) throws IOException {
        File DOMAIN_KEY_FILE = new File(sslDir + domain + File.separator + DOMAIN_KEY_FILENAME);
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
                return domainKeyPair;
            }
        }
    }

    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        Account account = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKey).create(session);
        log("注册URL: " + account.getLocation());
        return account;
    }

    private void getSSL(String domain) {
        log("申请SSL:" + domain);
        mkDir(sslDir + domain);

        Collection<String> domains = Arrays.asList(domain, "*." + domain);
        try {
            // Load the user key file. If there is no key file, create a new one.
            KeyPair userKeyPair = loadOrCreateUserKeyPair(domain);

            // Create a session for Let's Encrypt.
            // Use "acme://letsencrypt.org" for production server
            Session session = new Session("acme://letsencrypt.org/");

            // Get the Account.
            // If there is no account yet, create a new one.
            Account acct = findOrRegisterAccount(session, userKeyPair);

            // Load or create a key pair for the domains. This should not be the userKeyPair!
            KeyPair domainKeyPair = loadOrCreateDomainKeyPair(domain);

            // Order the certificate
            Order order = acct.newOrder().domains(domains).create();

            // Perform all required authorizations
            for (Authorization auth : order.getAuthorizations()) {
                authorize(auth, domain);
                log("域名认证成功");
            }

            // Order the certificate
            order.execute(domainKeyPair);

            // Wait for the order to complete
            try {
                int attempts = 10;
                while (order.getStatus() != Status.VALID && attempts-- > 0) {
                    // Did the order fail?
                    if (order.getStatus() == Status.INVALID) {
                        log("下订出错原因:" + order.getError().map(Problem::toString).orElse("unknown"));
                        throw new AcmeException("下单出错... 放弃SSL申请.");
                    }

                    // Wait for a few seconds
                    Thread.sleep(3000L);

                    // Then update the status
                    order.update();
                }
            } catch (InterruptedException ex) {
                log("出错:" + ex.getMessage());
                Thread.currentThread().interrupt();
            }

            // Get the certificate
            Certificate certificate = order.getCertificate();

            log("证书申请成功:" + domains);
            //log("证书地址:" + certificate.getLocation());

            try (FileWriter fw = new FileWriter(sslDir + domain + File.separator + DOMAIN_CHAIN_FILENAME)) {
                certificate.writeCertificate(fw);
            }
        } catch (Exception ex) {
            log("证书生成失败:" + domains + " 原因:" + ex.getMessage());
        }
    }

    private void authorize(Authorization auth, String domain) throws AcmeException {
        log("准备域名认证:" + auth.getIdentifier().getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge = dnsChallenge(auth, domain);

        if (challenge == null) {
            throw new AcmeException("没有找到需要的认证记录，请重试");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    log("认证失败原因: " + challenge.getError().map(Problem::toString).orElse("unknown"));
                    throw new AcmeException("认证失败... 放弃认证.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            log("出错:" + ex.getMessage());
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("认证记录对比失败... 放弃认证.");
        }

        // log("Challenge has been completed. Remember to remove the validation resource.");
    }

    public Challenge dnsChallenge(Authorization auth, String domain) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE).map(Dns01Challenge.class::cast).orElseThrow(() -> new AcmeException("域名认证失败...未找到认证记录，请重试"));
        log(Dns01Challenge.toRRName(auth.getIdentifier()) + " IN TXT " + challenge.getDigest());
        addAliDNS(domain, challenge.getDigest());
        return challenge;
    }

    private void addAliDNS(String domain, String digest) {
        AddDomainRecordRequest addRequest = new AddDomainRecordRequest();
        addRequest.setType("TXT");
        addRequest.setDomainName(domain);
        addRequest.setRR(Dns01Challenge.RECORD_NAME_PREFIX);
        addRequest.setValue(digest);

        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        IAcsClient client = new DefaultAcsClient(profile);
        try {
            AddDomainRecordResponse addResponse = client.getAcsResponse(addRequest);
            log("增加阿里域名TXT解析成功: " + addResponse.getRecordId());
        } catch (ClientException e) {
            log("增加阿里域名TXT解析失败,原因: " + e.getMessage());
        }
    }

    private void exitAPP() {
        log("程序退出");
        System.exit(0);
    }

    private void log(String txt) {
        String logTxt = LocalDateTime.now().format(timeFormat) + " " + txt + System.lineSeparator();
        try {
            String logfile = logDir + LocalDateTime.now().format(dateFormat) + ".txt";
            File file = new File(logfile);
            if (!file.exists()) {
                if (!file.createNewFile()) {
                    System.out.println("警告:日志文件创建失败!无法保存日志!请检查是否有权限创建logs文件夹!");
                }
            }
            FileWriter writer;
            writer = new FileWriter(file, true);
            writer.append(logTxt);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println(logTxt);
    }

    private Properties getProperties() {
        try {
            InputStream is = Files.newInputStream(Paths.get(jarDir + configFile));
            Properties pros = new Properties();
            pros.load(is);
            return pros;
        } catch (IOException e) {
            log(configFile + " 不能读取conf.properties配置文件 \n");
        }
        return null;
    }

    public boolean judgeOs() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.startsWith("windows");
    }

    private void reloadWindowNginx() {
        log("执行:" + nginxPath + " -s reload");
//      nginxPath = "D:\\Program Files\\nginx-1.17.10";
        try {
            String myExe = "cmd /c start nginx -s reload";

            File dir = new File(nginxPath);
            String[] str = new String[]{};
            // 执行命令
            Runtime.getRuntime().exec(myExe, str, dir);
        } catch (Exception ex) {
            log("执行出错:" + ex.getMessage());
        }
    }

    private void reloadLinuxNginx() {
        log("执行:" + nginxPath + " -s reload");
//      nginxPath = "/usr/local/nginx/sbin/";
        String command1 = nginxPath + "nginx -s reload";
        try {
            executeCmd2(command1);
        } catch (Exception ex) {
            log("执行出错:" + ex.getMessage());
        }
    }

    public void executeCmd2(String command) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = br.readLine()) != null) {
            log(line);
        }
    }
}