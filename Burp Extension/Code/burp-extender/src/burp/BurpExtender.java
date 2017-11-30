package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.net.URL;
import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.PrintWriter;

import burp.ITab;

public class BurpExtender implements IBurpExtender, IHttpListener, IContextMenuFactory, ITab
{
    private IBurpExtenderCallbacks  callbacks;
    private IExtensionHelpers       helpers;
    private PrintWriter             stdout;
    private HttpClient              client;
    private HttpPost                detector;

    private static String         pythonServer            = "http://127.0.0.1:9981";
    private static String         grepPhrase            = "T@lAcNow1Na0??";

    public JPanel                 mainPanel;
    public JPanel                 configPanel;
    public JTextField             pythonURL;
    public JTextField             grepPhraseTextfield;



    public String getTabCaption() {

        return "Fuzz 18+";
    }

    public Component getUiComponent() {

        return this.mainPanel;
    }

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // set our extension name
        callbacks.setExtensionName("18+");
        
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        helpers = callbacks.getHelpers();

        client = HttpClientBuilder.create().build();

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable() {

            public void run() {

                BurpExtender.this.mainPanel = new JPanel(new GridLayout(4, 1));
                BurpExtender.this.configPanel = new JPanel(new GridLayout(4, 1));
                /*
                 Server Config
                 */
                BurpExtender.this.pythonURL = new JTextField(25);
                BurpExtender.this.pythonURL.setText(BurpExtender.pythonServer);
        
                
                JLabel pythonURLTextfieldHeading = new JLabel("Python Server Adress:");
                BurpExtender.this.configPanel.add(pythonURLTextfieldHeading);
                BurpExtender.this.configPanel.add(BurpExtender.this.pythonURL);   

                BurpExtender.this.grepPhraseTextfield = new JTextField(25);
                BurpExtender.this.grepPhraseTextfield.setText(BurpExtender.grepPhrase);
        
                
                JLabel grepPhraseTextfieldHeading = new JLabel("Grep Phrase:");
                BurpExtender.this.configPanel.add(grepPhraseTextfieldHeading);
                BurpExtender.this.configPanel.add(BurpExtender.this.grepPhraseTextfield);  

                BurpExtender.this.mainPanel.add(configPanel);
     
                
               
                BurpExtender.this.callbacks.customizeUiComponent(BurpExtender.this.mainPanel);
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
 
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpReqRsp)
    {
        boolean isIntruder = (toolFlag==32);
        if (isIntruder) {
            if (!messageIsRequest) {
                sendToDetector(httpReqRsp, "response" ,"analyzer");
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] httpReqRsp = invocation.getSelectedMessages();
        if (httpReqRsp != null && httpReqRsp.length > 0) {
            stdout.println("Messages in array: " + httpReqRsp.length);
            List<JMenuItem> list = new ArrayList<JMenuItem>();
            // final IHttpService service = messages[0].getHttpService();
            JMenuItem menuItem = new JMenuItem("Send to Fuzz 18+");
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        stdout.println("call sendToDetector");
                        sendToDetector(httpReqRsp[0],"request" ,"fuzzer");
                        stdout.println("Finis sendToDetector");
                    } catch (Exception e1) {
                        stdout.println("Error action event");
                        stdout.println(e1.getMessage());
                    }
                }
            });
            list.add(menuItem);
            return list;
        }

        return null;
    }

    public void sendToDetector(IHttpRequestResponse httpReqRsp, String type, String mode) 
    {
        String protocol = httpReqRsp.getHttpService().getProtocol();
        String host = httpReqRsp.getHttpService().getHost();
        String port = String.valueOf(httpReqRsp.getHttpService().getPort());
        byte[] httpData = null;
        switch (mode) {
            case "fuzzer":
                httpData = httpReqRsp.getRequest();
                break;
            case "analyzer":
                httpData = httpReqRsp.getResponse();
                break;
        }
        String stringHttpData = this.helpers.bytesToString(httpData);
        stdout.println("Print HTTP");
        stdout.println(stringHttpData);


        stdout.println("Try to send out");
        byte[] encodedBytes = Base64.encodeBase64(httpData);
        String encodedHttpData = helpers.bytesToString(encodedBytes);
        List nameValuePairs = new ArrayList(6);
        nameValuePairs.add(new BasicNameValuePair("protocol", protocol));
        nameValuePairs.add(new BasicNameValuePair("host", host));
        nameValuePairs.add(new BasicNameValuePair("port", port));
        nameValuePairs.add(new BasicNameValuePair("data", encodedHttpData));
        nameValuePairs.add(new BasicNameValuePair("type", type));
        nameValuePairs.add(new BasicNameValuePair("mode", mode));
        stdout.println("Prepare send out");
        try {
            detector = new HttpPost(this.pythonURL.getText());

            detector.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            stdout.println("setted entity");

            HttpResponse response = this.client.execute(detector);
            stdout.println("Sended out");
            // Print out the response message
            String responseAsString = EntityUtils.toString(response.getEntity());
            stdout.println("Responed");
            this.stdout.println("Response: " + responseAsString);
        } catch (Exception e2) {
            stdout.println("error sendToDetector");
            stdout.println(e2.getMessage());

        }


    }


}