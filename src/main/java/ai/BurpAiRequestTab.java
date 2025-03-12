package ai;

import burp.api.montoya.ai.chat.PromptResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.safety.Safelist;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;

public class BurpAiRequestTab extends JPanel
{
    private final Logging logging;
    private final ExecutorService executorService;
    private final PromptHandler promptHandler;

    public BurpAiRequestTab(Logging logging, UserInterface userInterface, ExecutorService executorService, PromptHandler promptHandler, HttpRequestResponse requestResponse) {
        this.logging = logging;
        this.executorService = executorService;
        this.promptHandler = promptHandler;

        this.setLayout(new BorderLayout());

        // Create split panes for layout with specific orientation
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, true);
        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true);

        // Initialize editors using class field
        HttpRequestEditor requestEditor = userInterface.createHttpRequestEditor();
        HttpResponseEditor responseEditor = userInterface.createHttpResponseEditor();

        if (requestResponse != null) {
            requestEditor.setRequest(requestResponse.request());
            responseEditor.setResponse(requestResponse.response());
        }

        // Create AI response area with minimum size
        JEditorPane aiResponseArea = new JEditorPane();
        aiResponseArea.setContentType("text/html");
        aiResponseArea.setEditable(false);
        JScrollPane aiScrollPane = new JScrollPane(aiResponseArea);
        aiScrollPane.setPreferredSize(new Dimension(800, 200));

        // Add components to splits and set preferred sizes
        horizontalSplit.setLeftComponent(requestEditor.uiComponent());
        horizontalSplit.setRightComponent(responseEditor.uiComponent());
        horizontalSplit.setResizeWeight(0.5);

        verticalSplit.setTopComponent(horizontalSplit);
        verticalSplit.setBottomComponent(aiScrollPane);
        verticalSplit.setResizeWeight(0.7);

        // Set divider locations
        horizontalSplit.setDividerLocation(0.5);
        verticalSplit.setDividerLocation(0.7);

        this.add(verticalSplit, BorderLayout.CENTER);

        // Create a bottom panel with a FlowLayout and uniform spacing
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));

        // New checkbox
        JCheckBox includeReqResp = new JCheckBox("Send Request and Response");
        includeReqResp.setSelected(requestResponse != null);

        // Create a custom input field for additional user prompt
        JTextField customInputField = new JTextField(20);
        customInputField.setPreferredSize(new Dimension(200, 35));

        // Add analyze button with custom styling
        JButton analyzeButton = new JButton("Analyze with AI HTTP Analyzer");
        analyzeButton.setBackground(Color.decode("#ff6633"));
        analyzeButton.setForeground(Color.WHITE);
        //analyzeButton.setFont(new Font("Segoe UI Emoji", 13));
        analyzeButton.setFocusPainted(false);
        analyzeButton.setBorderPainted(false);
        analyzeButton.setOpaque(true);

        // Make button thicker
        analyzeButton.setPreferredSize(new Dimension(analyzeButton.getPreferredSize().width, 35));
        analyzeButton.setMargin(new Insets(5, 10, 5, 10));

        // Add new checkbox, input field, and button
        bottomPanel.add(includeReqResp);
        bottomPanel.add(customInputField);
        bottomPanel.add(analyzeButton);
        this.add(bottomPanel, BorderLayout.SOUTH);

        Consumer<AWTEvent> runPrompt = e -> {
            analyzeRequest(
                    requestEditor.getRequest(),
                    responseEditor.getResponse(),
                    aiResponseArea,
                    includeReqResp.isSelected(),
                    customInputField.getText());
            // Clear the input field
            customInputField.setText("");
        };

        customInputField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    runPrompt.accept(e);
                }
            }
        });

        analyzeButton.addActionListener(runPrompt::accept);
    }

    private void analyzeRequest(HttpRequest request,
                                HttpResponse response,
                                JEditorPane aiResponseArea,
                                boolean includeRequestResponse,
                                String customInput) {
        String promptText = buildPromptText(includeRequestResponse, customInput, request, response);

        if (promptText == null) {
            aiResponseArea.setText("Empty custom prompt or HTTP request.");
            return;
        }

        aiResponseArea.setText("Analyzing request/response...");

        // Set AI response text to 12px
        aiResponseArea.setFont(new Font(aiResponseArea.getFont().getFamily(), Font.PLAIN, 12));

        // Execute the AI prompt in a separate thread
        executorService.execute(() -> {
            try {
                PromptResponse aiResponse = promptHandler.sendWithSystemMessage(promptText);

                String content = aiResponse.content();

                // Remove any backticks before converting to HTML
                if (content.contains("`")) {
                    content = content.replaceAll("`+", "");
                }

                // Sanitize the HTML content to remove potentially dangerous elements
                Document.OutputSettings outputSettings = new Document.OutputSettings();
                outputSettings.prettyPrint(false);
                String sanitizedContent = Jsoup.clean(content, "", Safelist.basic(), outputSettings);

                // Convert Markdown to HTML
                Parser parser = Parser.builder().build();
                HtmlRenderer renderer = HtmlRenderer.builder().build();
                String htmlContent = renderer.render(parser.parse(sanitizedContent));

                logging.logToOutput("AI response received successfully");
                SwingUtilities.invokeLater(() ->
                        aiResponseArea.setText(htmlContent)
                );
            } catch (Exception error) {
                String errorDetails = "An unexpected error occurred: " + error.getMessage() + "\n\n" +
                        "Please check the Burp Suite extension logs for more details.";
                logging.logToError(errorDetails);
                SwingUtilities.invokeLater(() ->
                        aiResponseArea.setText(errorDetails)
                );
            }
        });
    }

    private static String buildPromptText(boolean includeRequestResponse, String customInput, HttpRequest request, HttpResponse response) {
        boolean analyzeRequest = includeRequestResponse && request != null;

        if (!analyzeRequest && customInput.isEmpty()) {
            return null;
        }

        // Build the prompt conditionally
        StringBuilder promptBuilder = new StringBuilder();

        if (analyzeRequest) {
            promptBuilder.append("Analyze this HTTP request");

            if (response != null) {
                promptBuilder.append(" and response");
            }

            promptBuilder
                    .append(" for security issues:\n")
                    .append("REQUEST:\n")
                    .append(request);

            if (response != null) {
                promptBuilder
                        .append("\n\nRESPONSE:\n")
                        .append(response);
            }

            promptBuilder.append("\n\n");
        }

        // Always append the custom prompt, regardless of checkbox
        promptBuilder.append(customInput);

        return promptBuilder.toString();
    }
}
