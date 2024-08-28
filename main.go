package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2/google"
)

const (
	CHRONICLE_API_BASE_URL = "https://chronicle.googleapis.com"
)

const (
	CHATGPT_API_URL = "https://api.openai.com/v1/chat/completions"
	CHATGPT_PROMPT  = `
Analyze the provided JSON output from a security event detection system and create a concise summary with the following structure:

## OUTCOME:
**MALICIOUS** or **NOT MALICIOUS** (select one). Most Security Operation Analysts work hundreds of cases per day, and the majority are false positives. That does not mean everything is not malicious, but keep that in mind when making a decision.

1. Event Overview:
    Detection Type
    Alert ID
    Creation Time
    Detection Time

2. Rule Details:
    Rule Name
    Rule Description
    Rule ID
    Rule Version
    Alert State
    Risk Score

3. MITRE ATT&CK Information:
    Tactic (TA)
    Technique (T1)
    MITRE URL
    Describe what the identified TA and T1 actually mean. For example, TA0006 is Credential Access and T1558.003 is Steal or Forge Kerberos Tickets: Kerberoasting

4. Event Specifics:
    Time Window (Start and End)
    Principal Details:
      Hostname
      IP Address(es)
      Username
    Principal Process Details:
      Command Line
      File Path
      SHA256 Hash
    Target Details:
      Hostname
      IP Address(es)
      Username
      Administrative Domain
      Application
    Target Process Details:
      Command Line
      File Path
      SHA256 Hash
    Key Actions or Observations

5. Critical Highlights:
    Emphasize any high-severity or unusual aspects and explain why it was marked malicious or not malicious. Make sure to say "I've decided this is (malicious or not malicious) because.. and then the reason.
    Depending if it's malicious or not malicious, indicate why something could potentially be the opposite. For example, nltest is normally not malicious, but it can be used to enumerate domain controllers and is often used by threat actors. If you have information, provide feedback on where threat actors may abuse it.
    Note any potential false positive indicators
    Highlight any security results or additional relevant information

6. Recommended Next Steps:
    Suggest immediate actions or further investigation points based on the event details

7. VirusTotal Summary:
    Briefly summarize the VirusTotal results, including the number of checks performed, how many were flagged as malicious, and any errors encountered.

Please provide your analysis in a clear, spaced format, adhering to these guidelines:

1. Include only sections and information that are explicitly present in the JSON data.
2. Omit entire sections (including their headers) if no relevant data is found in the JSON.
3. Do not use placeholders like "N/A" or "Not Available". If a field is empty or missing, simply exclude it from your summary.
4. Focus on highlighting the most critical elements for quick review.
5. Ensure that your summary directly reflects the content of the JSON, without adding speculative or filler information.

Remember, it's better to have a shorter, more accurate summary than a longer one with placeholder or speculative information. Your summary should be a direct representation of the data provided in the JSON, omitting any sections or fields for which no data is available.

When analyzing the JSON:
- Only include a section if you find concrete data for it.
- Within each section, only list fields that have actual values in the JSON.
- If an entire section (like Target Details) is empty in the JSON, completely omit that section from your summary.
- Do not create or infer information that isn't explicitly stated in the JSON data.

Your goal is to provide a concise, accurate summary that reflects only the information present in the provided JSON, highlighting the most relevant details for security analysis.
`
)

var (
	maliciousStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)
	notMaliciousStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#00FF00")).
				Bold(true)
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#874BFD")).
			Padding(1).
			MarginRight(1)
)

var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500")).
			Bold(true).
			MarginBottom(1)

	subHeaderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ADD8E6")).
			Bold(true)

	contentStyle = lipgloss.NewStyle().
			MarginLeft(2).
			MarginBottom(1)
)

type AISummary struct {
	Outcome              string
	EventOverview        string
	RuleDetails          string
	MitreAttackInfo      string
	EventSpecifics       string
	CriticalHighlights   string
	RecommendedNextSteps string
	VirusTotalSummary    string
}

func wrapText(text string, width int) string {
	lines := strings.Split(text, "\n")
	var wrappedLines []string
	for _, line := range lines {
		words := strings.Fields(strings.TrimSpace(line))
		if len(words) == 0 {
			wrappedLines = append(wrappedLines, "")
			continue
		}
		wrapped := words[0]
		spaceLeft := width - len(wrapped)
		for _, word := range words[1:] {
			if len(word)+1 > spaceLeft {
				wrappedLines = append(wrappedLines, wrapped)
				wrapped = word
				spaceLeft = width - len(word)
			} else {
				wrapped += " " + word
				spaceLeft -= 1 + len(word)
			}
		}
		wrappedLines = append(wrappedLines, wrapped)
	}
	return strings.Join(wrappedLines, "\n")
}

func (m model) getPanelWidths() (int, int) {
	panelWidth := (m.width - 4) / 2 // Subtract 4 for margins
	return panelWidth, panelWidth
}

func parseAISummary(summary string) AISummary {
	var result AISummary
	sections := strings.Split(summary, "\n\n")

	for _, section := range sections {
		if strings.HasPrefix(section, "## OUTCOME:") {
			result.Outcome = strings.TrimSpace(strings.TrimPrefix(section, "## OUTCOME:"))
		} else if strings.HasPrefix(section, "1. Event Overview:") {
			result.EventOverview = strings.TrimSpace(strings.TrimPrefix(section, "1. Event Overview:"))
		} else if strings.HasPrefix(section, "2. Rule Details:") {
			result.RuleDetails = strings.TrimSpace(strings.TrimPrefix(section, "2. Rule Details:"))
		} else if strings.HasPrefix(section, "3. MITRE ATT&CK Information:") {
			result.MitreAttackInfo = strings.TrimSpace(strings.TrimPrefix(section, "3. MITRE ATT&CK Information:"))
		} else if strings.HasPrefix(section, "4. Event Specifics:") {
			result.EventSpecifics = strings.TrimSpace(strings.TrimPrefix(section, "4. Event Specifics:"))
		} else if strings.HasPrefix(section, "5. Critical Highlights:") {
			result.CriticalHighlights = strings.TrimSpace(strings.TrimPrefix(section, "5. Critical Highlights:"))
		} else if strings.HasPrefix(section, "6. Recommended Next Steps:") {
			result.RecommendedNextSteps = strings.TrimSpace(strings.TrimPrefix(section, "6. Recommended Next Steps:"))
		} else if strings.HasPrefix(section, "7. VirusTotal Summary:") {
			result.VirusTotalSummary = strings.TrimSpace(strings.TrimPrefix(section, "7. VirusTotal Summary:"))
		}
	}

	return result
}

func renderOutcome(outcome string) string {
	if strings.ToUpper(outcome) == "MALICIOUS" {
		return maliciousStyle.Render("## OUTCOME: MALICIOUS")
	}
	return notMaliciousStyle.Render("## OUTCOME: NOT MALICIOUS")
}

func formatEventOverview(overview string) string {
	lines := strings.Split(overview, " - ")
	return strings.Join(lines, "\n\n")
}

func formatRuleDetails(details string) string {
	lines := strings.Split(details, " - ")
	return strings.Join(lines, "\n\n")
}

func formatDetectionDetails(details string) string {
	lines := strings.Split(details, "\n")
	var formattedLines []string
	var currentSection string
	isSubSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			formattedLines = append(formattedLines, "") // Add extra newline between sections
			continue
		}

		if strings.HasSuffix(line, ":") {
			// This is a main section header
			if currentSection != "" {
				formattedLines = append(formattedLines, "") // Add extra newline between sections
			}
			currentSection = line
			formattedLines = append(formattedLines, subHeaderStyle.Render(line))
			isSubSection = false
		} else if strings.Contains(line, ":") {
			// This is a key-value pair
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				formattedLines = append(formattedLines, fmt.Sprintf("%s: %s", lipgloss.NewStyle().Foreground(lipgloss.Color("#ADD8E6")).Render(key), value))
			} else {
				formattedLines = append(formattedLines, line)
			}
			isSubSection = false
		} else {
			// This is a continuation of the previous line or a new subsection
			if !isSubSection {
				formattedLines = append(formattedLines, "")
				isSubSection = true
			}
			formattedLines = append(formattedLines, line)
		}
	}
	return strings.Join(formattedLines, "\n")
}

func formatMitreInfo(info string) string {
	lines := strings.Split(info, " - ")
	return strings.Join(lines, "\n\n")
}

func formatVirusTotalSummary(summary string) string {
	lines := strings.Split(summary, " - ")
	return strings.Join(lines, "\n\n")
}

func (m model) renderDetailsPanel(summary AISummary) string {
	leftWidth, _ := m.getPanelWidths()
	contentWidth := leftWidth - 8 // Adjust for padding and margins

	formatSection := func(title string, content string) string {
		return fmt.Sprintf("%s\n%s",
			subHeaderStyle.Render(title),
			contentStyle.Render(wrapText(content, contentWidth)),
		)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		formatSection("Event Overview:", formatEventOverview(summary.EventOverview)),
		formatSection("Rule Details:", formatRuleDetails(summary.RuleDetails)),
		formatSection("MITRE ATT&CK Information:", formatMitreInfo(summary.MitreAttackInfo)),
		formatSection("VirusTotal Summary:", formatVirusTotalSummary(summary.VirusTotalSummary)),
	)

	return panelStyle.Width(leftWidth).Render(lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("Details"),
		content,
	))
}

func (m model) renderHighlightsPanel(summary AISummary) string {
	_, rightWidth := m.getPanelWidths()
	contentWidth := rightWidth - 8 // Adjust for padding and margins

	formatSection := func(title string, content string) string {
		return fmt.Sprintf("%s\n%s",
			subHeaderStyle.Render(title),
			contentStyle.Render(wrapText(content, contentWidth)),
		)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		formatSection("Critical Highlights:", summary.CriticalHighlights),
		formatSection("Recommended Next Steps:", summary.RecommendedNextSteps),
	)

	return panelStyle.Width(rightWidth).Render(lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("Highlights & Next Steps"),
		content,
	))
}

func (m model) renderDetectionDetailsPanel(summary AISummary) string {
	fullWidth := m.width - 4      // Adjust for margins
	contentWidth := fullWidth - 8 // Adjust for padding and margins

	formattedDetails := formatDetectionDetails(summary.EventSpecifics)
	wrappedContent := wrapText(formattedDetails, contentWidth)
	content := contentStyle.Render(wrappedContent)

	return panelStyle.Width(fullWidth).Render(lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("Detection Details"),
		content,
	))
}

func initDebugLogger() {
	// Removed debug logger initialization
}

func debugLog(format string, v ...interface{}) {
	// Removed debug log function body
}

func queryVirusTotal(hash string, apiKey string) (bool, error) {
	// Removed debug log calls
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected response format")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected response format")
	}

	lastAnalysisStats, ok := attributes["last_analysis_stats"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected response format")
	}

	malicious, ok := lastAnalysisStats["malicious"].(float64)
	if !ok {
		return false, fmt.Errorf("unexpected response format")
	}

	return malicious > 0, nil
}

type Rule struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Author      string `json:"author"`
	RuleID      string
}

func (r Rule) Title() string       { return r.DisplayName }
func (r Rule) Description() string { return "Rule ID: " + r.RuleID }
func (r Rule) FilterValue() string { return r.DisplayName }

type Detection struct {
	Type               string              `json:"type"`
	Detection          []RuleDetection     `json:"detection"`
	CreatedTime        time.Time           `json:"createdTime"`
	ID                 string              `json:"id"`
	TimeWindow         TimeWindow          `json:"timeWindow"`
	CollectionElements []CollectionElement `json:"collectionElements"`
	DetectionTime      time.Time           `json:"detectionTime"`
}

type RuleDetection struct {
	RuleName         string  `json:"ruleName"`
	Description      string  `json:"description"`
	URLBackToProduct string  `json:"urlBackToProduct"`
	RuleID           string  `json:"ruleId"`
	RuleVersion      string  `json:"ruleVersion"`
	AlertState       string  `json:"alertState"`
	RuleType         string  `json:"ruleType"`
	RuleLabels       []Label `json:"ruleLabels"`
	RiskScore        int     `json:"riskScore"`
}

type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TimeWindow struct {
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
}

type CollectionElement struct {
	References []Reference `json:"references"`
	Label      string      `json:"label"`
}

type Reference struct {
	Event Event `json:"event"`
}

type Event struct {
	Metadata       EventMetadata          `json:"metadata"`
	Additional     map[string]interface{} `json:"additional"`
	Principal      Principal              `json:"principal"`
	Target         Target                 `json:"target"`
	Intermediary   []Intermediary         `json:"intermediary"`
	Observer       Observer               `json:"observer"`
	About          []About                `json:"about"`
	SecurityResult []SecurityResult       `json:"securityResult"`
}

type EventMetadata struct {
	ProductLogID        string                 `json:"productLogId"`
	EventTimestamp      time.Time              `json:"eventTimestamp"`
	EventType           string                 `json:"eventType"`
	VendorName          string                 `json:"vendorName"`
	ProductName         string                 `json:"productName"`
	ProductEventType    string                 `json:"productEventType"`
	Description         string                 `json:"description"`
	IngestedTimestamp   time.Time              `json:"ingestedTimestamp"`
	ProductDeploymentID string                 `json:"productDeploymentId"`
	ID                  string                 `json:"id"`
	LogType             string                 `json:"logType"`
	BaseLabels          map[string]interface{} `json:"baseLabels"`
	EnrichmentLabels    map[string]interface{} `json:"enrichmentLabels"`
}

type Principal struct {
	Hostname  string   `json:"hostname"`
	Process   Process  `json:"process"`
	IP        []string `json:"ip"`
	Port      int      `json:"port"`
	MAC       []string `json:"mac"`
	Namespace string   `json:"namespace"`
	Asset     Asset    `json:"asset"`
	User      User     `json:"user"`
}

type Process struct {
	PID         string `json:"pid"`
	CommandLine string `json:"commandLine"`
	File        File   `json:"file"`
}

type File struct {
	SHA256   string `json:"sha256"`
	MD5      string `json:"md5"`
	SHA1     string `json:"sha1"`
	FullPath string `json:"fullPath"`
}

type Asset struct {
	Hostname string   `json:"hostname"`
	IP       []string `json:"ip"`
	MAC      []string `json:"mac"`
}

type Target struct {
	User                 User     `json:"user"`
	AdministrativeDomain string   `json:"administrativeDomain"`
	Application          string   `json:"application"`
	Resource             Resource `json:"resource"`
	Namespace            string   `json:"namespace"`
	Process              Process  `json:"process"`
	IP                   []string `json:"ip"`
	Hostname             string   `json:"hostname"`
}

type User struct {
	UserID     string `json:"userid"`
	WindowsSid string `json:"windowsSid"`
}

type Resource struct {
	Name            string `json:"name"`
	ResourceSubtype string `json:"resourceSubtype"`
}

type Intermediary struct {
	Hostname  string `json:"hostname"`
	Namespace string `json:"namespace"`
}

type Observer struct {
	Application string  `json:"application"`
	Namespace   string  `json:"namespace"`
	Labels      []Label `json:"labels"`
}

type About struct {
	Namespace string  `json:"namespace"`
	Labels    []Label `json:"labels"`
}

type SecurityResult struct {
	RuleName    string `json:"ruleName"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type model struct {
	list              list.Model
	allRules          []Rule
	filteredRules     []Rule
	searchInput       textinput.Model
	err               error
	nextPageToken     string
	loading           bool
	width             int
	height            int
	selectedRule      *Rule
	detections        []Detection
	viewState         string
	httpClient        *http.Client
	aiSummary         string
	detectionsList    list.Model
	selectedDetection *Detection
	spinner           spinner.Model
	waitingForSummary bool
	chatgptApiKey     string
}

type rulesMsg struct {
	rules         []Rule
	nextPageToken string
}

type detectionsMsg struct {
	detections []Detection
}

type errMsg error

type aiSummaryMsg string

type detectionItem struct {
	detection Detection
}

type tickMsg struct{}

func (i detectionItem) Title() string {
	return fmt.Sprintf("Detection ID: %s", i.detection.ID)
}

func (i detectionItem) Description() string {
	return fmt.Sprintf("Created: %s, Type: %s", i.detection.CreatedTime.Format(time.RFC3339), i.detection.Type)
}

func (i detectionItem) FilterValue() string {
	return i.detection.ID
}

func initialModel(chatgptApiKey string) model {
	ti := textinput.New()
	ti.Placeholder = "Search rules..."
	ti.Focus()

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return model{
		list:              list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0),
		searchInput:       ti,
		loading:           true,
		viewState:         "rules",
		detectionsList:    list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0),
		spinner:           s,
		waitingForSummary: false,
		chatgptApiKey:     chatgptApiKey,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		fetchRules(""),
		initializeHttpClient(),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit

		case tea.KeyEsc:
			switch m.viewState {
			case "rules":
				return m, tea.Quit
			case "detections":
				m.viewState = "rules"
				m.detections = nil
				m.selectedRule = nil
				return m, nil
			case "detection_summary":
				m.viewState = "detections"
				m.selectedDetection = nil
				m.aiSummary = ""
				m.waitingForSummary = false
				return m, nil
			}

		case tea.KeyTab:
			if m.viewState == "rules" {
				if m.searchInput.Focused() {
					m.searchInput.Blur()
				} else {
					m.searchInput.Focus()
				}
				return m, nil
			}

		case tea.KeyEnter:
			switch m.viewState {
			case "rules":
				selectedItem := m.list.SelectedItem()
				if selectedItem != nil {
					rule := selectedItem.(Rule)
					m.selectedRule = &rule
					return m, fetchLastWeekDetectionsCmd(rule.RuleID, m.httpClient)
				}
			case "detections":
				selectedItem := m.detectionsList.SelectedItem()
				if selectedItem != nil {
					detection := selectedItem.(detectionItem).detection
					m.selectedDetection = &detection
					m.waitingForSummary = true
					m.viewState = "detection_summary"
					return m, tea.Batch(
						generateAISummaryCmd(detection, m.chatgptApiKey),
						m.spinner.Tick,
					)
				}
			}

		default:
			if m.viewState == "rules" {
				if m.searchInput.Focused() {
					m.searchInput, cmd = m.searchInput.Update(msg)
					m.updateFilteredRules()
					return m, cmd
				} else {
					m.list, cmd = m.list.Update(msg)
					return m, cmd
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v-3)
		m.detectionsList.SetSize(msg.Width-h, msg.Height-v-3)

	case rulesMsg:
		m.allRules = append(m.allRules, msg.rules...)
		m.nextPageToken = msg.nextPageToken
		if m.nextPageToken != "" {
			return m, fetchRules(m.nextPageToken)
		}
		m.loading = false
		m.updateFilteredRules()

	case detectionsMsg:
		items := make([]list.Item, len(msg.detections))
		for i, d := range msg.detections {
			items[i] = detectionItem{d}
		}
		m.detectionsList.SetItems(items)
		m.viewState = "detections"
		return m, nil

	case aiSummaryMsg:
		m.aiSummary = string(msg)
		m.waitingForSummary = false
		return m, nil

	case errMsg:
		m.err = msg
		m.loading = false
		return m, nil

	case *http.Client:
		m.httpClient = msg

	case tickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	switch m.viewState {
	case "rules":
		m.list, cmd = m.list.Update(msg)
	case "detections":
		m.detectionsList, cmd = m.detectionsList.Update(msg)
	}

	return m, cmd
}

func (m *model) updateFilteredRules() {
	filter := strings.ToLower(m.searchInput.Value())
	if filter == "" {
		m.filteredRules = m.allRules
	} else {
		m.filteredRules = []Rule{}
		for _, rule := range m.allRules {
			if strings.Contains(strings.ToLower(rule.DisplayName), filter) ||
				strings.Contains(strings.ToLower(rule.RuleID), filter) {
				m.filteredRules = append(m.filteredRules, rule)
			}
		}
	}
	items := make([]list.Item, len(m.filteredRules))
	for i, rule := range m.filteredRules {
		items[i] = rule
	}
	m.list.SetItems(items)
}

func (m model) View() string {
	if m.err != nil {
		return fmt.Sprintf("Error: %v", m.err)
	}

	if m.loading {
		return "Loading rules... Please wait."
	}

	switch m.viewState {
	case "rules":
		focusText := "Tab to switch focus"
		if m.searchInput.Focused() {
			focusText = "Search: (Tab to focus list)"
		} else {
			focusText = "List: (Tab to focus search)"
		}
		return fmt.Sprintf(
			"%s\n%s\n\n%s\n\nTotal rules: %d",
			focusText,
			m.searchInput.View(),
			m.list.View(),
			len(m.allRules),
		)
	case "detections":
		return m.renderDetectionsList()
	case "detection_summary":
		return m.renderDetectionSummary()
	}

	return ""
}

func (m model) renderDetectionsList() string {
	var content strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		MarginBottom(1)

	content.WriteString(titleStyle.Render(fmt.Sprintf("Detections for Rule: %s (Last 7 days)", m.selectedRule.DisplayName)))
	content.WriteString("\n\n")
	content.WriteString(m.detectionsList.View())
	content.WriteString("\n\nPress Enter to view detection summary, ESC to go back")

	return content.String()
}

func (m model) renderDetectionSummary() string {
	var content strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		MarginBottom(1)

	content.WriteString(titleStyle.Render(fmt.Sprintf("Summary for Detection: %s", m.selectedDetection.ID)))
	content.WriteString("\n\n")

	if m.waitingForSummary {
		content.WriteString(fmt.Sprintf("%s Generating AI summary...\n", m.spinner.View()))
	} else {
		summary := parseAISummary(m.aiSummary)
		content.WriteString(renderOutcome(summary.Outcome))
		content.WriteString("\n\n")

		topRow := lipgloss.JoinHorizontal(lipgloss.Top,
			m.renderDetailsPanel(summary),
			m.renderHighlightsPanel(summary),
		)

		bottomRow := m.renderDetectionDetailsPanel(summary)

		content.WriteString(lipgloss.JoinVertical(lipgloss.Left, topRow, bottomRow))
	}

	content.WriteString("\n\nPress ESC to go back to detections list")

	return content.String()
}

func fetchRules(pageToken string) tea.Cmd {
	return func() tea.Msg {
		credFile := os.Getenv("CHRONICLE_CRED_FILE")
		projectID := os.Getenv("CHRONICLE_PROJECT_ID")
		instanceID := os.Getenv("CHRONICLE_INSTANCE_ID")
		region := os.Getenv("CHRONICLE_REGION")

		if region == "" {
			region = "us" // Default to "us" if not specified
		}

		data, err := ioutil.ReadFile(credFile)
		if err != nil {
			return errMsg(err)
		}

		conf, err := google.JWTConfigFromJSON(data, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return errMsg(err)
		}

		client := conf.Client(nil)

		baseURL := fmt.Sprintf("https://%s-chronicle.googleapis.com/v1alpha/projects/%s/locations/%s/instances/%s/rules",
			region, projectID, region, instanceID)

		u, err := url.Parse(baseURL)
		if err != nil {
			return errMsg(err)
		}

		q := u.Query()
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u.RawQuery = q.Encode()

		resp, err := client.Get(u.String())
		if err != nil {
			return errMsg(err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errMsg(err)
		}

		var result struct {
			Rules         []Rule `json:"rules"`
			NextPageToken string `json:"nextPageToken"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return errMsg(err)
		}

		for i := range result.Rules {
			parts := strings.Split(result.Rules[i].Name, "/")
			result.Rules[i].RuleID = parts[len(parts)-1]
		}

		return rulesMsg{rules: result.Rules, nextPageToken: result.NextPageToken}
	}
}

func fetchDetections(ruleId, alertState, startTime, endTime string, client *http.Client, region, projectID, instanceID string, pageToken string) ([]Detection, error) {
	baseURL := fmt.Sprintf("https://%s-chronicle.googleapis.com/v1alpha/projects/%s/locations/%s/instances/%s/legacy:legacySearchDetections",
		region, projectID, region, instanceID)

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("ruleId", ruleId)
	if alertState != "" {
		q.Set("alertState", alertState)
	}
	if startTime != "" {
		q.Set("startTime", startTime)
	}
	if endTime != "" {
		q.Set("endTime", endTime)
	}
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Detections    []Detection `json:"detections"`
		NextPageToken string      `json:"nextPageToken"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Detections, nil
}

func fetchLastWeekDetectionsCmd(ruleId string, client *http.Client) tea.Cmd {
	return func() tea.Msg {
		region := os.Getenv("CHRONICLE_REGION")
		projectID := os.Getenv("CHRONICLE_PROJECT_ID")
		instanceID := os.Getenv("CHRONICLE_INSTANCE_ID")

		endTime := time.Now().UTC()
		startTime := endTime.AddDate(0, 0, -90)

		detections, err := fetchDetections(ruleId, "", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), client, region, projectID, instanceID, "")
		if err != nil {
			return errMsg(err)
		}

		return detectionsMsg{detections: detections}
	}
}

func generateAISummary(detection Detection, chatgptApiKey string) (string, error) {
	jsonData, err := json.MarshalIndent(detection, "", "  ")
	if err != nil {
		return "", err
	}

	vtApiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if vtApiKey == "" {
		return "", fmt.Errorf("VirusTotal API key not set")
	}

	var vtResults []string
	checksPerformed := 0
	for _, ce := range detection.CollectionElements {
		for _, ref := range ce.References {
			if ref.Event.Principal.Process.File.SHA256 != "" {
				checksPerformed++
				isMalicious, err := queryVirusTotal(ref.Event.Principal.Process.File.SHA256, vtApiKey)
				if err != nil {
					vtResults = append(vtResults, fmt.Sprintf("Error checking Principal SHA256: %v", err))
				} else if isMalicious {
					vtResults = append(vtResults, fmt.Sprintf("Principal SHA256 (%s) flagged as malicious by VirusTotal", ref.Event.Principal.Process.File.SHA256))
				} else {
					vtResults = append(vtResults, fmt.Sprintf("Principal SHA256 (%s) not flagged as malicious by VirusTotal", ref.Event.Principal.Process.File.SHA256))
				}
			}

			if ref.Event.Target.Process.File.SHA256 != "" {
				checksPerformed++
				isMalicious, err := queryVirusTotal(ref.Event.Target.Process.File.SHA256, vtApiKey)
				if err != nil {
					vtResults = append(vtResults, fmt.Sprintf("Error checking Target SHA256: %v", err))
				} else if isMalicious {
					vtResults = append(vtResults, fmt.Sprintf("Target SHA256 (%s) flagged as malicious by VirusTotal", ref.Event.Target.Process.File.SHA256))
				} else {
					vtResults = append(vtResults, fmt.Sprintf("Target SHA256 (%s) not flagged as malicious by VirusTotal", ref.Event.Target.Process.File.SHA256))
				}
			}
		}
	}

	vtResultsStr := strings.Join(vtResults, "\n")
	if checksPerformed == 0 {
		vtResultsStr = "No VirusTotal checks were performed. This could be due to empty SHA256 hashes."
	} else if len(vtResults) == 0 {
		vtResultsStr = "VirusTotal checks were performed, but no significant results were found. All checked hashes were not flagged as malicious."
	}

	updatedPrompt := fmt.Sprintf("%s\n\nVirusTotal Results:\n%s\n\nPlease consider the VirusTotal results when determining the OUTCOME and explaining why it was marked malicious or not malicious.", CHATGPT_PROMPT, vtResultsStr)

	requestBody, err := json.Marshal(map[string]interface{}{
		"model": "gpt-4o",
		// "max_tokens": 2048,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": fmt.Sprintf("%s\n\nHere's the JSON data to analyze:\n%s", updatedPrompt, string(jsonData)),
			},
		},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", CHATGPT_API_URL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", chatgptApiKey))
	// req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Error: %d - %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	choices, ok := result["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("Unexpected response format")
	}

	firstChoice, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Unexpected choices format")
	}

	message, ok := firstChoice["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Unexpected message format")
	}

	text, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("Unexpected text format")
	}

	return text, nil
}

func generateAISummaryCmd(detection Detection, chatgptApiKey string) tea.Cmd {
	return func() tea.Msg {
		summary, err := generateAISummary(detection, chatgptApiKey)
		if err != nil {
			return errMsg(err)
		}
		return aiSummaryMsg(summary)
	}
}

func initializeHttpClient() tea.Cmd {
	return func() tea.Msg {
		credFile := os.Getenv("CHRONICLE_CRED_FILE")
		data, err := ioutil.ReadFile(credFile)
		if err != nil {
			return errMsg(err)
		}

		conf, err := google.JWTConfigFromJSON(data, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return errMsg(err)
		}

		client := conf.Client(nil)
		return client
	}
}

var docStyle = lipgloss.NewStyle().Margin(1, 2)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	chatgptApiKey := os.Getenv("CHATGPT_API_KEY")
	if chatgptApiKey == "" {
		fmt.Println("Error: CHATGPT_API_KEY environment variable is not set")
		os.Exit(1)
	}

	p := tea.NewProgram(initialModel(chatgptApiKey), tea.WithAltScreen())

	go func() {
		ticker := time.NewTicker(time.Millisecond * 100)
		for {
			<-ticker.C
			p.Send(tickMsg{})
		}
	}()

	if err := p.Start(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
