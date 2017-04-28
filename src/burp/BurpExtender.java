package burp;

import javax.swing.*;
import java.awt.*;
import javax.swing.text.NumberFormatter;
import javax.swing.border.EmptyBorder;
import java.text.NumberFormat;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

/**
 * Created by fruh on 8/30/16.
 */

public class BurpExtender implements IBurpExtender, IHttpListener, IContextMenuFactory, ITab {
    private static String EXTENSION_NAME = "ExtendedMacro";
    private static String EXTENSION_NAME_TAB_NAME = "Extended Macro";
    private static String VERSION = "0.0.4";
    public PrintWriter stdout;
    public PrintWriter stderr;
    public IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private MessagesTable extMessagesTable;
    private MessagesTable repMessagesTable;
    private JSplitPane mainPanel;
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
    private JCheckBox replaceUrlDecodeCheckbox;
    private int msgId = 0;
    private int msgIdLogger = 0;

    private long lastExtractionTime = 0l;
    private MessagesModel loggerMessagesModel;

    private JCheckBox boxRepeater;
    private JCheckBox boxIntruder;
    private JCheckBox boxScanner;
    private JCheckBox boxSequencer;
    private JCheckBox boxSpider;
    private JCheckBox boxProxy;
    private JFormattedTextField delayInput;

    static Color BURP_ORANGE = new Color(229, 137, 0);
    private Font headerFont = new Font("Nimbus", Font.BOLD, 13);

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
        return  boxIntruder.isSelected() ||
                boxRepeater.isSelected() ||
                boxScanner.isSelected() ||
                boxSequencer.isSelected() ||
                boxProxy.isSelected() ||
                boxSpider.isSelected();
    }

    public String getNextMsgId() {
        return String.valueOf(++msgId);
    }

    public String getNextMsgIdLogger() {
        return String.valueOf(++msgIdLogger);
    }

    private void initGui() {
        mainTabPane = new JTabbedPane();

        JSplitPane mainPanel_up = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JPanel p1 = new JPanel();
        JPanel p2 = new JPanel();
        JPanel p3 = new JPanel();

        p1.setLayout(new GridLayout(1, 2));
        p2.setLayout(new GridLayout(1, 2));
        p3.setLayout(new GridLayout(1, 2));

        mainPanel_up.add(p1);
        mainPanel_up.add(p2);
        mainPanel.add(mainPanel_up);
        mainPanel.add(p3);

        p1.setPreferredSize(new Dimension(100, 200));
        p2.setPreferredSize(new Dimension(100, 500));
        p3.setPreferredSize(new Dimension(100, 80));

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

        p1.add(extMessagesTab);

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

        p1.add(repMessagesTab);

        // add editor tabs
        p2.add(extMessagesTabs);
        p2.add(repMessagesTabs);

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
        p3.add(extTab);

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
        replaceType.addItem(Replace.TYPE_REP_BURP);
        replaceType.addItem(Replace.TYPE_ADD_BURP);
        replaceType.addItem(Replace.TYPE_REP_HEADER_BURP);
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

        replaceUrlDecodeCheckbox = new JCheckBox("", false);

        replaceButtonsPane.add(new JLabel("URL decode:"));
        replaceButtonsPane.add(replaceUrlDecodeCheckbox);

        repCreateButton = new JButton("Add");
        repCreateButton.setEnabled(false);
        repFromSelectionButton = new JButton("From selection");
        repFromSelectionButton.setEnabled(true);

        repCreateButton.addActionListener(new ConfigListener(this, ConfigActions.A_CREATE_NEW_REP));
        repFromSelectionButton.addActionListener(new ConfigListener(this, ConfigActions.A_REP_FROM_SELECTION));

        replaceButtonsPane.add(repCreateButton);
        replaceButtonsPane.add(repFromSelectionButton);

        replacePanel.add(replaceButtonsPane);
        p3.add(repTab);

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
        p1.revalidate();
        p2.revalidate();
        p3.revalidate();

        p1.repaint();
        p2.repaint();
        p3.repaint();
        initSettingsGui(mainTabPane);
    }

    private void initSettingsGui(JTabbedPane mainTabPane){
        boxRepeater = new JCheckBox("Repeater", true);
        boxIntruder = new JCheckBox("Intruder", true);
        boxScanner = new JCheckBox("Scanner", true);
        boxSequencer = new JCheckBox("Sequencer", true);
        boxSpider = new JCheckBox("Spider", true);
        boxProxy = new JCheckBox("Proxy", false);

        JLabel header1 = new JLabel("Tools scope");
        header1.setAlignmentX(Component.LEFT_ALIGNMENT);
        header1.setForeground(BURP_ORANGE);
        header1.setFont(headerFont);
        header1.setBorder(new EmptyBorder(5, 0, 5, 0));

        JLabel label2 = new JLabel("Select the tools that the pre-request macro will be applied to.");
        label2.setAlignmentX(Component.LEFT_ALIGNMENT);
        label2.setBorder(new EmptyBorder(0, 0, 10, 0));

        JButton toggleScopesButton = new JButton("All/None");

        toggleScopesButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        toggleScopesButton.addActionListener(new ConfigListener(this, ConfigActions.A_ENABLE_DISABLE));

        // Scope
        JPanel scopePanel = new JPanel();
        scopePanel.setBorder(new EmptyBorder(10, 0, 10, 0));

        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.LINE_AXIS));
        scopePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel col1 = new JPanel();
        col1.setLayout(new BoxLayout(col1, BoxLayout.PAGE_AXIS));
        col1.add(boxRepeater);
        col1.add(boxIntruder);
        col1.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel col2 = new JPanel();
        col2.setLayout(new BoxLayout(col2, BoxLayout.PAGE_AXIS));
        col2.add(boxScanner);
        col2.add(boxSequencer);
        col2.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel col3 = new JPanel();
        col3.setLayout(new BoxLayout(col3, BoxLayout.PAGE_AXIS));
        col3.add(boxSpider);
        col3.add(boxProxy);
        col3.setAlignmentY(Component.TOP_ALIGNMENT);

        scopePanel.add(col1);
        scopePanel.add(col2);
        scopePanel.add(col3);

        // Other settings
        JLabel header2 = new JLabel("Other settings");
        header2.setAlignmentX(Component.LEFT_ALIGNMENT);
        header2.setForeground(BURP_ORANGE);
        header2.setFont(headerFont);
        header2.setBorder(new EmptyBorder(5, 0, 5, 0));

        JLabel delayLabel = new JLabel("Extraction caching (in seconds, 0 = make extraction every request):");

        NumberFormat format = NumberFormat.getInstance();
        NumberFormatter formatter = new NumberFormatter(format);
        formatter.setValueClass(Integer.class);
        formatter.setMinimum(0);
        formatter.setMaximum(Integer.MAX_VALUE);
        formatter.setAllowsInvalid(false);
        delayInput = new JFormattedTextField(formatter);
        delayInput.setMinimumSize(delayInput.getPreferredSize());
        delayInput.setColumns(2);

        delayInput.setValue(0); // default is zero delay - extraction is done everytime

        JPanel delayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        delayPanel.add(delayLabel);
        delayPanel.add(delayInput);
        delayPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Put it all together
        JPanel confPanel = new JPanel();
        confPanel.setLayout(new BoxLayout(confPanel, BoxLayout.Y_AXIS));
        confPanel.setBorder(new EmptyBorder(5, 15, 5, 15));

        confPanel.add(header1);
        confPanel.add(label2);
        confPanel.add(toggleScopesButton);
        confPanel.add(scopePanel);

        confPanel.add(header2);
        confPanel.add(delayPanel);

        mainTabPane.addTab("Settings", confPanel);
    }

    public void setAllTools(boolean enabled) {
        boxRepeater.setSelected(enabled);
        boxIntruder.setSelected(enabled);
        boxScanner.setSelected(enabled);
        boxSequencer.setSelected(enabled);
        boxSpider.setSelected(enabled);
        boxProxy.setSelected(enabled);
    }

    private int getExtractionDelay(){
        return (Integer) delayInput.getValue();
    }

    public boolean isToolEnabled(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return boxIntruder.isSelected();

            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return boxRepeater.isSelected();

            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return boxScanner.isSelected();

            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return boxSequencer.isSelected();

            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return boxSpider.isSelected();

            case IBurpExtenderCallbacks.TOOL_PROXY:
                return boxProxy.isSelected();
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
        else if (messagesModel.getMessages().size() > 0){
            // TODO: the sequence is not correct in multihreaded
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
        return EXTENSION_NAME_TAB_NAME;
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

    public JCheckBox getReplaceUrlDecodeCheckbox() {
        return replaceUrlDecodeCheckbox;
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

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
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
        if (replaceTypeString.equals(Replace.TYPE_ADD_BURP) ||
                replaceTypeString.equals(Replace.TYPE_REP_BURP) ||
                replaceTypeString.equals(Replace.TYPE_REP_HEADER_BURP)) {
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
