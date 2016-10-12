package burp;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by fruh on 9/7/16.
 */
public class Message {
    private IHttpRequestResponse messageInfo;
    private String id;
    private Set<String> repRefSet;
    private Set<String> extRefSet;

    public Message(IHttpRequestResponse messageInfo, String id) {
        this.messageInfo = messageInfo;
        this.id = id;
        repRefSet = new HashSet<>();
        extRefSet = new HashSet<>();
    }

    public IHttpRequestResponse getMessageInfo() {
        return messageInfo;
    }

    public void setMessageInfo(IHttpRequestResponse messageInfo) {
        this.messageInfo = messageInfo;
    }

    public Set<String> getRepRefSet() {
        return repRefSet;
    }

    public Set<String> getExtRefSet() {
        return extRefSet;
    }

    public boolean hasExtraction() {
        return extRefSet.size() > 0;
    }

    public boolean hasReplace() {
        return repRefSet.size() > 0;
    }

    public String getId() {
        return id;
    }
}
