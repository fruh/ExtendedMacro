package burp;

import javax.swing.*;
import java.awt.*;
import javax.swing.text.NumberFormatter;
import java.text.NumberFormat;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

/**
 * Created by fruh on 8/30/16.
 */

public class BurpExtender implements IBurpExtender, IHttpListener, IContextMenuFactory, ITab {
    private static String EXTENSION_NAME = "ExtendedMacro";
    private static String VERSION = "v0.0.2";
    public PrintWriter stdout;
    public PrintWriter stderr;
    public IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private MessagesTable extMessagesTable;
    private MessagesTable repMessagesTable;
    private JPanel mainPanel;
    private MessagesModel messagesModel;
    private IMessageEditor extRequestEditor;
    private IMessageEditor extResponseEditor;
    private IMessageEditor repRequestEditor;
    private IMessageEditor repResponseEditor;
    private MessagesController extMessagesController;
    private MessagesController repMessagesController;
    private Set<String> actualCallRepSet; /// what to replace in last call
    private ExtractionModel extractionModel;
    private ExtractionTable extractionTable;
    private ReplaceModel replaceModel;
    private ReplaceTable replaceTable;
    private JButton repCreateButton;
    private JButton repFromSelectionButton;
    private JTabbedPane mainTabPane;

    private JTextArea startStringField;
    private JTextArea stopStringField;
    private JTextArea extractedStringField;
    private JTextField extractionNameStringField;
    private JButton extCreateButton;
    private JButton extFromSelectionButton;

    private JTextArea replaceStringField;
    private JComboBox<String> replaceType;
    private JTextField replaceNameStringField;
    private int msgId = 0;
    private int msgIdLogger = 0;

    private long lastExtractionTime = 0l;
    private MessagesModel loggerMessagesModel;

    private JCheckBox repeater;
    private JCheckBox intruder;
    private JCheckBox scanner;
    private JCheckBox sequencer;
    private JCheckBox spider;
    private JCheckBox proxy;
    private JFormattedTextField extractionDelayInput;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        helpers = callbacks.getHelpers();

        actualCallRepSet = new HashSet<>();

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName(EXTENSION_NAME);

        initGui();

        // register callbacks
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);

        // init gui callbacks
        callbacks.addSuiteTab(this);

        stdout.println("[*] " + EXTENSION_NAME + " " + VERSION);
    }

    public boolean isEnabledAtLeastOne() {
        return intruder.isSelected() ||
                repeater.isSelected() ||
                scanner.isSelected() ||
                sequencer.isSelected() ||
                proxy.isSelected() ||
                spider.isSelected();
    }

    public String getNextMsgId() {
        return String.valueOf(++msgId);
    }

    public String getNextMsgIdLogger() {
        return String.valueOf(++msgIdLogger);
    }

    private void initGui() {
        mainTabPane = new JTabbedPane();

        mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayout(3, 2));

        messagesModel = new MessagesModel(this.helpers);

        // extraction messages table
        extMessagesTable = new MessagesTable(this, false);
        extMessagesTable.setModel(messagesModel);
        extMessagesTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        extMessagesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        extMessagesTable.getTableHeader().getColumnModel().getColumn(0).setMaxWidth(100);
        extMessagesTable.getTableHeader().getColumnModel().getColumn(1).setPreferredWidth(200);
        extMessagesTable.getTableHeader().getColumnModel().getColumn(2).setMaxWidth(100);
        extMessagesTable.getTableHeader().getColumnModel().getColumn(3).setPreferredWidth(800);

        messagesModel.setExtMsgTable(extMessagesTable);

        // popup menu for messages
        JPopupMenu extPopupMenu = new JPopupMenu();
        extPopupMenu.add("Remove").addActionListener(
                new MenuListener(this, MenuActions.A_REMOVE_MSG, extMessagesTable));
        extPopupMenu.add("Remove all").addActionListener(
                new MenuListener(this, MenuActions.A_REMOVE_ALL, extMessagesTable));
        extPopupMenu.add("Move up").addActionListener(
                new MenuListener(this, MenuActions.A_MOVE_UP_EXT, extMessagesTable));
        extPopupMenu.add("Move down").addActionListener(
                new MenuListener(this, MenuActions.A_MOVE_DOWN_EXT, extMessagesTable));

        extMessagesTable.setComponentPopupMenu(extPopupMenu);

        // create controller
        extMessagesController = new MessagesController(extMessagesTable);
        extRequestEditor = callbacks.createMessageEditor(extMessagesController, false);
        extResponseEditor = callbacks.createMessageEditor(extMessagesController, false);

        extMessagesTable.setReq(extRequestEditor);
        extMessagesTable.setRes(extResponseEditor);
        extMessagesTable.setCtrl(extMessagesController);

        JTabbedPane extMessagesTabs = new JTabbedPane();
        extMessagesTabs.addTab("Request", extRequestEditor.getComponent());
        extMessagesTabs.addTab("Response", extResponseEditor.getComponent());
        extMessagesTabs.setSelectedIndex(1);

        JScrollPane extMsgScrollPane = new JScrollPane(extMessagesTable);
        JTabbedPane extMessagesTab = new JTabbedPane();
        extMessagesTab.addTab("Extraction message list", extMsgScrollPane);

        mainPanel.add(extMessagesTab);

        // replace messages table
        repMessagesTable = new MessagesTable(this, false);
        repMessagesTable.setModel(messagesModel);
        repMessagesTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        repMessagesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        repMessagesTable.getTableHeader().getColumnModel().getColumn(0).setMaxWidth(100);
        repMessagesTable.getTableHeader().getColumnModel().getColumn(1).setPreferredWidth(200);
        repMessagesTable.getTableHeader().getColumnModel().getColumn(2).setMaxWidth(100);
        repMessagesTable.getTableHeader().getColumnModel().getColumn(3).setPreferredWidth(800);

        messagesModel.setRepMsgTable(repMessagesTable);

        JPopupMenu repPopupMenu = new JPopupMenu();
        repPopupMenu.add("Remove").addActionListener(new MenuListener(this, MenuActions.A_REMOVE_MSG, repMessagesTable));
        repPopupMenu.add("Remove all").addActionListener(new MenuListener(this, MenuActions.A_REMOVE_ALL, repMessagesTable));
        repPopupMenu.add("Move up").addActionListener(new MenuListener(this, MenuActions.A_MOVE_UP_REP, repMessagesTable));
        repPopupMenu.add("Move down").addActionListener(new MenuListener(this, MenuActions.A_MOVE_DOWN_REP, repMessagesTable));

        repMessagesTable.setComponentPopupMenu(repPopupMenu);

        // create controller
        repMessagesController = new MessagesController(repMessagesTable);
        repRequestEditor = callbacks.createMessageEditor(repMessagesController, false);
        repResponseEditor = callbacks.createMessageEditor(repMessagesController, false);
//        repRespEditor = callbacks.createTextEditor();

        repMessagesTable.setReq(repRequestEditor);
        repMessagesTable.setRes(repResponseEditor);
        repMessagesTable.setCtrl(repMessagesController);


        JTabbedPane repMessagesTabs = new JTabbedPane();
        repMessagesTabs.addTab("Request", repRequestEditor.getComponent());
        repMessagesTabs.addTab("Response", repResponseEditor.getComponent());

        JScrollPane repMsgScrollPane = new JScrollPane(repMessagesTable);
        JTabbedPane repMessagesTab = new JTabbedPane();
        repMessagesTab.addTab("Replace message list", repMsgScrollPane);

        mainPanel.add(repMessagesTab);

        // add editor tabs
        mainPanel.add(extMessagesTabs);
        mainPanel.add(repMessagesTabs);

        // extraction panel
        JPanel extractionPanel = new JPanel();
        extractionPanel.setLayout(new GridLayout(0, 2));
        extractionModel = new ExtractionModel(this);
        extractionTable = new ExtractionTable(this);
        extractionTable.setModel(extractionModel);
        extractionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        messagesModel.setExtractionTable(extractionTable);

        JPopupMenu extConfPopupMenu = new JPopupMenu();
        extConfPopupMenu.add("Remove").addActionListener(new ConfigListener(this, ConfigActions.A_DELETE_SEL_EXT));
        extConfPopupMenu.add("Remove all").addActionListener(new ConfigListener(this, ConfigActions.A_DELETE_ALL_EXT));

        extractionTable.setComponentPopupMenu(extConfPopupMenu);

        JTabbedPane extTab = new JTabbedPane();
        JScrollPane extScrollPane = new JScrollPane(extractionTable);
        extractionPanel.add(extScrollPane);
        extTab.addTab("Extraction configuration", extractionPanel);

        JPanel extButtonsPane = new JPanel();
        extButtonsPane.setLayout(new GridLayout(0, 2));

        startStringField = new JTextArea();
        stopStringField = new JTextArea();
        extractedStringField = new JTextArea();
        extractionNameStringField = new JTextField();

        startStringField.getDocument().addDocumentListener(
                new ConfigChangedListener(this, ConfigActions.A_EXT_CONFIG_CHANGED));
        stopStringField.getDocument().addDocumentListener(
                new ConfigChangedListener(this, ConfigActions.A_EXT_CONFIG_CHANGED));
        extractionNameStringField.getDocument().addDocumentListener(
                new ConfigChangedListener(this, ConfigActions.A_EXT_VALIDITY));
        getExtractedStringField().setEditable(false);

        extButtonsPane.add(new JLabel("Name:"));
        extButtonsPane.add(extractionNameStringField);
        extButtonsPane.add(new JLabel("Start string:"));
        extButtonsPane.add(startStringField);
        extButtonsPane.add(new JLabel("Stop string:"));
        extButtonsPane.add(stopStringField);
        extButtonsPane.add(new JLabel("Extracted string:"));
        extButtonsPane.add(extractedStringField);

        extCreateButton = new JButton("Add");
        extCreateButton.setEnabled(false);
        extFromSelectionButton = new JButton("From selection");
        extFromSelectionButton.setEnabled(true);

        extCreateButton.addActionListener(new ConfigListener(this, ConfigActions.A_CREATE_NEW_EXT));
        extFromSelectionButton.addActionListener(new ConfigListener(this, ConfigActions.A_EXT_FROM_SELECTION));

        extButtonsPane.add(extCreateButton);
        extButtonsPane.add(extFromSelectionButton);

        extractionPanel.add(extButtonsPane);
        mainPanel.add(extTab);

        // replace panel
        JPanel replacePanel = new JPanel();
        replacePanel.setLayout(new GridLayout(0, 2));
        replaceModel = new ReplaceModel(this);
        replaceTable = new ReplaceTable(this);
        replaceTable.setModel(replaceModel);
        replaceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        messagesModel.setReplaceTable(replaceTable);

        JPopupMenu repConfPopupMenu = new JPopupMenu();
        repConfPopupMenu.add("Remove").addActionListener(new ConfigListener(this, ConfigActions.A_DELETE_SEL_REP));
        repConfPopupMenu.add("Remove all").addActionListener(new ConfigListener(this, ConfigActions.A_DELETE_ALL_REP));

        replaceTable.setComponentPopupMenu(repConfPopupMenu);

        JTabbedPane repTab = new JTabbedPane();
        JScrollPane repScrollPane = new JScrollPane(replaceTable);
        replacePanel.add(repScrollPane);
        repTab.addTab("Replace configuration", replacePanel);

        JPanel replaceButtonsPane = new JPanel();
        replaceButtonsPane.setLayout(new GridLayout(0, 2));

        replaceStringField = new JTextArea();
        replaceType = new JComboBox<>();
        replaceType.addItem(Replace.TYPE_REP_SEL);
        replaceType.addItem(Replace.TYPE_ADD_SEL);
        replaceType.addItem(Replace.TYPE_REP_LAST);
        replaceType.addItem(Replace.TYPE_ADD_LAST);
        replaceType.addItem(Replace.TYPE_REP_HEADER_LAST);
        replaceNameStringField = new JTextField();

        replaceType.addActionListener(new ConfigChangedListener(this, ConfigActions.A_REP_CONFIG_CHANGED));
        replaceStringField.getDocument().addDocumentListener(
                new ConfigChangedListener(this, ConfigActions.A_REP_CONFIG_CHANGED));
        replaceNameStringField.getDocument().addDocumentListener(
                new ConfigChangedListener(this, ConfigActions.A_REP_CONFIG_CHANGED));

        replaceButtonsPane.add(new JLabel("Name:"));
        replaceButtonsPane.add(replaceNameStringField);
        replaceButtonsPane.add(new JLabel("Type:"));
        replaceButtonsPane.add(replaceType);
        replaceButtonsPane.add(new JLabel("Replace/Header name:"));
        replaceButtonsPane.add(replaceStringField);

        repCreateButton = new JButton("Add");
        repCreateButton.setEnabled(false);
        repFromSelectionButton = new JButton("From selection");
        repFromSelectionButton.setEnabled(true);

        repCreateButton.addActionListener(new ConfigListener(this, ConfigActions.A_CREATE_NEW_REP));
        repFromSelectionButton.addActionListener(new ConfigListener(this, ConfigActions.A_REP_FROM_SELECTION));

        replaceButtonsPane.add(repCreateButton);
        replaceButtonsPane.add(repFromSelectionButton);

        replacePanel.add(replaceButtonsPane);
        mainPanel.add(repTab);

        mainTabPane.addTab("Main window", mainPanel);

        // Logger pane
        loggerMessagesModel = new MessagesModel(this.helpers);

        // logger messages table
        MessagesTable loggerMessagesTable = new MessagesTable(this, true);
        loggerMessagesTable.setModel(loggerMessagesModel);
        loggerMessagesTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        loggerMessagesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        loggerMessagesTable.getTableHeader().getColumnModel().getColumn(0).setMaxWidth(200);
        loggerMessagesTable.getTableHeader().getColumnModel().getColumn(0).setPreferredWidth(100);
        loggerMessagesTable.getTableHeader().getColumnModel().getColumn(1).setPreferredWidth(100);
        loggerMessagesTable.getTableHeader().getColumnModel().getColumn(2).setMaxWidth(100);
        loggerMessagesTable.getTableHeader().getColumnModel().getColumn(3).setPreferredWidth(800);

        JScrollPane loggerMsgScrollPane = new JScrollPane(loggerMessagesTable);

        // create controller
        MessagesController loggerMessagesController = new MessagesController(loggerMessagesTable);
        IMessageEditor loggerRequestEditor = callbacks.createMessageEditor(loggerMessagesController, false);
        IMessageEditor loggerResponseEditor = callbacks.createMessageEditor(loggerMessagesController, false);

        loggerMessagesTable.setReq(loggerRequestEditor);
        loggerMessagesTable.setRes(loggerResponseEditor);
        loggerMessagesTable.setCtrl(loggerMessagesController);

        JPopupMenu loggerPopupMenu = new JPopupMenu();
        loggerPopupMenu.add("Remove all").addActionListener(
                new MenuListener(this, MenuActions.A_REMOVE_ALL, loggerMessagesTable));
        loggerMessagesTable.setComponentPopupMenu(loggerPopupMenu);

        JSplitPane logger = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
//        logger.setLayout(new GridLayout(0, 1));

        JPanel loggerMessagesEditorPanel = new JPanel();
        loggerMessagesEditorPanel.setLayout(new GridLayout(0, 2));

        JTabbedPane loggerReq = new JTabbedPane();
        loggerReq.addTab("Request", loggerRequestEditor.getComponent());

        JTabbedPane loggerRes = new JTabbedPane();
        loggerRes.add("Response", loggerResponseEditor.getComponent());

        loggerMessagesEditorPanel.add(loggerReq);
        loggerMessagesEditorPanel.add(loggerRes);

        logger.add(loggerMsgScrollPane);
        logger.add(loggerMessagesEditorPanel);

        mainTabPane.addTab("Logger", logger);

        // configuration tab
        JPanel confPanel = new JPanel();

        confPanel.setLayout(new BoxLayout(confPanel, BoxLayout.Y_AXIS));
        //confPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel settingsTool = new JLabel("Select what tools are enabled:");
        settingsTool.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton enDisTool = new JButton("All/None");
        enDisTool.setAlignmentX(Component.LEFT_ALIGNMENT);

        repeater = new JCheckBox("Repeater");
        intruder = new JCheckBox("Intruder");
        scanner = new JCheckBox("Scanner");
        sequencer = new JCheckBox("Sequencer");
        spider = new JCheckBox("Spider");
        proxy = new JCheckBox("Proxy");



        NumberFormat format = NumberFormat.getInstance();
        NumberFormatter formatter = new NumberFormatter(format);
        formatter.setValueClass(Integer.class);
        formatter.setMinimum(0);
        formatter.setMaximum(Integer.MAX_VALUE);
        formatter.setAllowsInvalid(false);
        // If you want the value to be committed on each keystroke instead of focus lost
        //formatter.setCommitsOnValidEdit(true);
        extractionDelayInput = new JFormattedTextField(formatter);
        extractionDelayInput.setMinimumSize(extractionDelayInput.getPreferredSize());

        // default is zero delay - extraction is done everytime
        extractionDelayInput.setValue(new Integer(0));


        repeater.setSelected(true);
        intruder.setSelected(true);
        scanner.setSelected(true);
        sequencer.setSelected(true);
        spider.setSelected(true);
        proxy.setSelected(false);

        JPanel desc1Panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        desc1Panel.add(settingsTool);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(enDisTool);
        buttonPanel.add(repeater);
        buttonPanel.add(intruder);
        buttonPanel.add(scanner);
        buttonPanel.add(sequencer);
        buttonPanel.add(spider);
        buttonPanel.add(proxy);

        enDisTool.addActionListener(new ConfigListener(this, ConfigActions.A_ENABLE_DISABLE));

        JPanel extrPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel extrDelayDesc = new JLabel("Select what tools are enabled:");

        extrPanel.add(extractionDelayInput);

        confPanel.add(desc1Panel);
        confPanel.add(buttonPanel);
        confPanel.add(extrPanel);
        confPanel.add(Box.createVerticalGlue());

        mainTabPane.addTab("Settings", confPanel);
    }

    private Component leftJustify(JPanel panel)  {
        Box b = Box.createHorizontalBox();
        b.add(panel);
        b.add(Box.createHorizontalGlue());
        return b;
    }


    public void setAllTools(boolean enabled) {
        repeater.setSelected(enabled);
        intruder.setSelected(enabled);
        scanner.setSelected(enabled);
        sequencer.setSelected(enabled);
        spider.setSelected(enabled);
        proxy.setSelected(enabled);
    }

    private int getExtractionDelay(){
        return (Integer) extractionDelayInput.getValue();
    }

    public boolean isToolEnabled(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return intruder.isSelected();

            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return repeater.isSelected();

            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return scanner.isSelected();

            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return sequencer.isSelected();

            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return spider.isSelected();

            case IBurpExtenderCallbacks.TOOL_PROXY:
                return proxy.isSelected();
        }
        return false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // ignore disabled tools and check if it is turned on
        if (!isToolEnabled(toolFlag)) {
            return;
        }
        if (messageIsRequest) {
//            stdout.println("[*] Processing request");

            // get list of requests
            List<Message> messages = messagesModel.getMessages();
            String newRequest;
            String extractedData;

            long currentTime = System.currentTimeMillis();
            long difference = currentTime - lastExtractionTime;
            if (difference > getExtractionDelay() * 1000l){
                stdout.println("[+] Extraction is being done, time since the last (s): " + difference/1000 + ", delay is " + getExtractionDelay()
                        + " s");
                lastExtractionTime = currentTime;

                // do extraction
                for (Message m : messages) {
                    newRequest = new String(m.getMessageInfo().getRequest());

                    // there is something to replace
                    if (m.hasReplace()) {
                        for (String repId : m.getRepRefSet()) {
                            stdout.println("[*] Replacing repId:" + repId);
                            newRequest = replaceModel.getReplaceById(repId).replaceData(newRequest, helpers);
                        }
                    }
                    // make updated request
                    IHttpRequestResponse newMsgInfo = callbacks.makeHttpRequest(
                            m.getMessageInfo().getHttpService(), newRequest.getBytes());
                    // log message
                    loggerMessagesModel.addMessage(newMsgInfo, getNextMsgIdLogger());

                    // there is something to extract from received response
                    if (m.hasExtraction()) {
                        for (String extId: m.getExtRefSet()) {
                            extractedData = extractionModel.getExtractionById(extId).extractData(
                                    new String(newMsgInfo.getResponse()));
                            // update replace references
                            for (String repId : extractionModel.getExtractionById(extId).getRepRefSet()) {
                                replaceModel.getReplaceById(repId).setDataToPaste(extractedData);
                            }
                        }
                    }
                }
            } else {
                stdout.println("[-] No extraction being done, time since the last (s): " + difference/1000 + ", delay is " + getExtractionDelay() + "ss");
            }

            // replace data in the last request, it is not in the message list
            for (Replace rep : replaceModel.getReplacesLast()) {
                newRequest = rep.replaceData(new String(messageInfo.getRequest()), helpers);
                messageInfo.setRequest(newRequest.getBytes());
            }
        }
        else {
            // TODO: the sequnce is not correct in multihreaded
            String fromTool = "UNKNOWN TOOL";

            switch (toolFlag) {
                case IBurpExtenderCallbacks.TOOL_INTRUDER:
                    fromTool = "INTRUDER";

                    break;
                case IBurpExtenderCallbacks.TOOL_REPEATER:
                    fromTool = "REPEATER";

                    break;
                case IBurpExtenderCallbacks.TOOL_SCANNER:
                    fromTool = "SCANNER";

                    break;
                case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                    fromTool = "SEQUENCER";

                    break;
                case IBurpExtenderCallbacks.TOOL_SPIDER:
                    fromTool = "SPIDER";

                    break;
                case IBurpExtenderCallbacks.TOOL_PROXY:
                    fromTool = "PROXY";

                    break;
            }
            // log response
            loggerMessagesModel.addMessage(messageInfo, getNextMsgIdLogger() + " " + fromTool);
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        stdout.println("[*] processing menu");

        if (messages.length > 0) {
            List<JMenuItem> menu = new LinkedList<>();
            JMenuItem sendTo = new JMenuItem("Send to " + EXTENSION_NAME);
            sendTo.addActionListener(new MenuListener(this, messages, MenuActions.A_SEND_TO_EM, getExtMessagesTable()));

            menu.add(sendTo);

            return menu;
        }
        return null;
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainTabPane;
    }

    public JTextArea getStartStringField() {
        return startStringField;
    }

    public JTextArea getStopStringField() {
        return stopStringField;
    }

    public JTextArea getExtractedStringField() {
        return extractedStringField;
    }

    public JTextField getExtractionNameStringField() {
        return extractionNameStringField;
    }

    public JTextArea getReplaceStringField() {
        return replaceStringField;
    }

    public JComboBox<String> getReplaceType() {
        return replaceType;
    }

    public JTextField getReplaceNameStringField() {
        return replaceNameStringField;
    }

    public MessagesTable getExtMessagesTable() {
        return extMessagesTable;
    }

    public MessagesTable getRepMessagesTable() {
        return repMessagesTable;
    }

    public IMessageEditor getExtResponseEditor() {
        return extResponseEditor;
    }

    public MessagesController getExtMessagesController() {
        return extMessagesController;
    }

    public MessagesController getRepMessagesController() {
        return repMessagesController;
    }

    public MessagesModel getMessagesModel() {
        return messagesModel;
    }

    public ExtractionModel getExtractionModel() {
        return extractionModel;
    }

    public ReplaceModel getReplaceModel() {
        return replaceModel;
    }

    public ExtractionTable getExtractionTable() {
        return extractionTable;
    }

    public ReplaceTable getReplaceTable() {
        return replaceTable;
    }

    public void setEnabledExtCreateButton() {
        extCreateButton.setEnabled(isValidExtraction());
    }

    public void setEnabledRepCreateButton() {
        repCreateButton.setEnabled(isValidReplace());
    }

    /**
     * Check whether it is possible to create extraction point.
     * @return
     */
    public boolean isValidExtraction() {
        if (extMessagesTable.getSelectedRow() >= 0 &&
                !extractionNameStringField.getText().isEmpty() &&
                !startStringField.getText().isEmpty() &&
                !stopStringField.getText().isEmpty() &&
                !getExtractedStringField().getText().isEmpty() &&
                !getExtractedStringField().getText().equals("EXTRACTION_ERROR")) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Check whether it is possible to create replace rule. The replace message must be selected and must be
     * after the current extraction message. The extraction must be selected.
     * The name (id) and the replace string must be set.
     * @return
     */
    public boolean isValidReplace() {
        int repMsgRow = repMessagesTable.getSelectedRow();
        int extRow = extractionTable.getSelectedRow();
        boolean ignore_rep_row = false;


        String replaceTypeString = replaceType.getSelectedItem().toString();
        if (replaceTypeString.equals(Replace.TYPE_ADD_LAST) ||
                replaceTypeString.equals(Replace.TYPE_REP_LAST) ||
                replaceTypeString.equals(Replace.TYPE_REP_HEADER_LAST)) {
            ignore_rep_row = true;
        }

        if ((repMsgRow >= 0 || ignore_rep_row) &&
                !replaceNameStringField.getText().isEmpty() &&
                !replaceStringField.getText().isEmpty() &&
                extRow >= 0
                ) {
            int extMsgRow = ((MessagesModel)extMessagesTable.getModel()).getRowById(
                    extractionModel.getExtraction(extRow).getMsgId());
            // replacing or adding header, must be selected only the following message
            if ((replaceTypeString.equals(Replace.TYPE_ADD_SEL) ||
                    replaceTypeString.equals(Replace.TYPE_REP_SEL)) &&
                    // trying to replace in the previous or same message
                    repMsgRow <= extMsgRow) {
                stdout.println("[-] Can not replace on previous or same message.");

                return false;
            }
            return canBeReplacedOnSelected();
        }
        return false;
    }

    public boolean canBeReplacedOnSelected() {
        if (replaceType.getSelectedItem().toString() == Replace.TYPE_REP_SEL) {
            Message msg = repMessagesController.getSelectedMessage();

            if (msg != null) {
//                ITextEditor textEditor = (ITextEditor)repRequestEditor.getComponent().getClass().getClasses();
//                repRespEditor.setSearchExpression(replaceStringField.getText());
                // TODO: set search string

                String request = new String(msg.getMessageInfo().getRequest());
                int index = request.indexOf(replaceStringField.getText());

                if (index < 0) {
                    replaceStringField.setBackground(Color.red);

                    return false;
                }
            }
        }
        return true;
    }

    public void setReplaceStringBackground() {
        if (canBeReplacedOnSelected()) {
            replaceStringField.setBackground(Color.white);
        }
        else {
            replaceStringField.setBackground(Color.red);
        }
    }

    public boolean canBeMoved(MenuActions direction) {
        boolean ret = true;
        Message msg;
        int row;

        switch (direction) {
            case A_MOVE_UP_EXT:
                msg = extMessagesController.getSelectedMessage();
                row = extMessagesTable.getSelectedRow();

                if (msg != null) {
                    for (String repId: msg.getRepRefSet()) {
                        String extMsgId = replaceModel.getReplaceById(repId).getExt().getMsgId();
                        // can not be moved up because it gets data from previous msg
                        if (row - 1 <= messagesModel.getRowById(extMsgId)) {
                            stdout.println(
                                    "[-] Message can not be moved up, because of getting data from previous msg");
                            ret = false;
                            break;
                        }
                    }
                }
                break;

            case A_MOVE_UP_REP:
                msg = repMessagesController.getSelectedMessage();
                row = repMessagesTable.getSelectedRow();

                if (msg != null) {
                    for (String repId: msg.getRepRefSet()) {
                        String extMsgId = replaceModel.getReplaceById(repId).getExt().getMsgId();
                        // can not be moved up because it gets data from previous msg
                        if (row - 1 <= messagesModel.getRowById(extMsgId)) {
                            stdout.println(
                                    "[-] Message can not be moved up, because of getting data from previous msg");
                            ret = false;
                            break;
                        }
                    }
                }
                break;

            case A_MOVE_DOWN_EXT:
                msg = extMessagesController.getSelectedMessage();
                row = extMessagesTable.getSelectedRow();

                if (msg != null) {
                    for (String extId: msg.getExtRefSet()) {
                        String extMsgId = extractionModel.getExtractionById(extId).getMsgId();
                        // can not be moved down, because of extracting data for following msg
                        if (row + 1 >= messagesModel.getRowById(extMsgId)) {
                            stdout.println(
                                    "[-] Message can not be moved down, because of extracting data for following msg");
                            ret = false;
                            break;
                        }
                    }
                }
                break;

            case A_MOVE_DOWN_REP:
                msg = repMessagesController.getSelectedMessage();
                row = repMessagesTable.getSelectedRow();

                if (msg != null) {
                    for (String extId: msg.getExtRefSet()) {
                        String extMsgId = extractionModel.getExtractionById(extId).getMsgId();
                        // can not be moved down, because of extracting data for following msg
                        if (row + 1 >= messagesModel.getRowById(extMsgId)) {
                            stdout.println(
                                    "[-] Message can not be moved down, because of extracting data for following msg");
                            ret = false;
                            break;
                        }
                    }
                }
                break;
        }
        return ret;
    }

    public IMessageEditor getRepRequestEditor() {
        return repRequestEditor;
    }
}
