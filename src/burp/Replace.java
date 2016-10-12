package burp;

import java.util.List;

/**
 * Created by fruh on 9/7/16.
 */
public class Replace {
    public static String TYPE_REP_SEL = "Replace on selected";
    public static String TYPE_ADD_SEL = "Add new header on selected";
    public static String TYPE_REP_LAST = "Replace on last request";
    public static String TYPE_ADD_LAST = "Add new header on last request";

    private String dataToPaste;
    private String replaceStr;
    private String id;
    private String type;
    private String msgId;
    private Extraction ext;

    public Replace(String id, String replaceStr, String type, Extraction ext) {
        this.id = id;
        this.replaceStr = replaceStr;
        this.type = type;
        this.ext = ext;
    }

    public String getDataToPaste() {
        return dataToPaste;
    }

    public void setDataToPaste(String dataToPaste) {
        this.dataToPaste = dataToPaste;
    }

    public String getReplaceStr() {
        return replaceStr;
    }

    public void setReplaceStr(String replaceStr) {
        this.replaceStr = replaceStr;
    }

    public String replaceData(IHttpRequestResponse messageInfo, IExtensionHelpers helpers) {
        String request = new String(messageInfo.getRequest());

        if (type == TYPE_REP_SEL || type == TYPE_REP_LAST) {
            request = request.replace(replaceStr, dataToPaste);
        }
        else {
            IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = rqInfo.getHeaders();
            headers.add(replaceStr + ": " + dataToPaste);

            String msgBody = request.substring(rqInfo.getBodyOffset());
            request = new String(helpers.buildHttpMessage(headers, msgBody.getBytes()));
        }
        return request;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getMsgId() {
        return msgId;
    }

    public void setMsgId(String msgId) {
        this.msgId = msgId;
    }

    public String getExtId() {
        return ext.getId();
    }

    public Extraction getExt() {
        return ext;
    }

    @Override
    public String toString() {
        return "'" + id + "', '" + type + "', '" + replaceStr + "', '" + msgId + "'";
    }
}
