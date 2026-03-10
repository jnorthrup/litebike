import AppKit
import Foundation

private enum DefaultsKey {
    static let workspaceRoot = "litebike.controlplane.workspaceRoot"
}

private enum OperatorAction: String, CaseIterable {
    case buildRelease = "build-release"
    case proxySSH = "proxy-ssh"
    case openSSHTerminal = "open-ssh-terminal"
    case gitPushCurrent = "git-push-current"
    case deployRemote = "deploy-remote"
    case proxyStatus = "proxy-status"
    case proxyStop = "proxy-stop"
    case syncTermux = "sync-termux"

    var title: String {
        switch self {
        case .buildRelease:
            return "Build Release"
        case .gitPushCurrent:
            return "Git Push"
        case .deployRemote:
            return "Remote Deploy"
        case .proxyStatus:
            return "Proxy Status"
        case .proxySSH:
            return "Proxy SSH Start"
        case .proxyStop:
            return "Proxy Stop"
        case .syncTermux:
            return "Sync Termux"
        case .openSSHTerminal:
            return "Open SSH Terminal"
        }
    }

    var summary: String {
        switch self {
        case .buildRelease:
            return "cargo build --release"
        case .gitPushCurrent:
            return "Push the current branch to origin"
        case .deployRemote:
            return "Push current branch and build on the remote host"
        case .proxyStatus:
            return "Inspect proxy-bridge status"
        case .proxySSH:
            return "Start the remote proxy via SSH"
        case .proxyStop:
            return "Stop proxy-bridge services"
        case .syncTermux:
            return "Refresh local termux/* tracking branches"
        case .openSSHTerminal:
            return "Open an interactive SSH shell in Terminal.app"
        }
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var statusItem: NSStatusItem?
    private var window: NSWindow?
    private var outputView: NSTextView?
    private var workspaceField: NSTextField?
    private var currentProcess: Process?
    private var outputPipe: Pipe?
    private let bundledWorkspaceRoot = Bundle.main.object(forInfoDictionaryKey: "LitebikeWorkspaceRoot") as? String

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        setupWindow()
        updateWorkspaceDisplay()
        showWindow(nil)

        appendOutput("Litebike Operator Bar ready.\n")
        if let workspaceURL = currentWorkspaceURL() {
            appendOutput("Workspace: \(workspaceURL.path)\n")
        } else {
            appendOutput("Choose a litebike workspace to enable actions.\n")
        }
        appendOutput("Remote actions use LB_HOST, LB_USER, LB_SSH_PORT, LB_DIR, LB_REMOTE_BUILD_CMD, and LB_REMOTE_AFTER_BUILD_CMD.\n\n")
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            showWindow(nil)
        }
        return true
    }

    func windowWillClose(_ notification: Notification) {
        NSApp.hide(nil)
    }

    @objc
    private func showWindow(_ sender: Any?) {
        guard let window else { return }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc
    private func chooseWorkspace(_ sender: Any?) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Use Workspace"
        panel.message = "Select the litebike workspace the operator bar should control."
        if let workspaceURL = currentWorkspaceURL() {
            panel.directoryURL = workspaceURL
        }

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }

        UserDefaults.standard.set(url.path, forKey: DefaultsKey.workspaceRoot)
        updateWorkspaceDisplay()
        appendOutput("Workspace updated to \(url.path)\n")
    }

    @objc
    private func clearOutput(_ sender: Any?) {
        outputView?.string = ""
    }

    @objc
    private func stopCurrentTask(_ sender: Any?) {
        guard let currentProcess else {
            appendOutput("No task is currently running.\n")
            return
        }
        appendOutput("Stopping task \(currentProcess.processIdentifier)...\n")
        currentProcess.terminate()
    }

    @objc
    private func copyWorkspacePath(_ sender: Any?) {
        guard let workspaceURL = currentWorkspaceURL() else {
            appendOutput("Choose a workspace before copying its path.\n")
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(workspaceURL.path, forType: .string)
        appendOutput("Copied workspace path.\n")
    }

    @objc
    private func quit(_ sender: Any?) {
        currentProcess?.terminate()
        NSApp.terminate(nil)
    }

    @objc
    private func runMappedAction(_ sender: Any?) {
        let rawValue: String?
        if let button = sender as? NSButton {
            rawValue = button.identifier?.rawValue
        } else if let item = sender as? NSMenuItem {
            rawValue = item.representedObject as? String
        } else {
            rawValue = nil
        }

        guard let rawValue, let action = OperatorAction(rawValue: rawValue) else {
            return
        }
        runAction(action)
    }

    private func runAction(_ action: OperatorAction) {
        guard currentProcess == nil else {
            appendOutput("A task is already running. Stop it before launching \(action.title).\n")
            return
        }
        guard let workspaceURL = currentWorkspaceURL() else {
            appendOutput("Choose a workspace before running \(action.title).\n")
            return
        }
        guard let scriptURL = actionScriptURL() else {
            appendOutput("Missing bundled action script.\n")
            return
        }

        let process = Process()
        process.executableURL = scriptURL
        process.arguments = [action.rawValue]
        process.currentDirectoryURL = workspaceURL

        var environment = ProcessInfo.processInfo.environment
        environment["LITEBIKE_REPO_ROOT"] = workspaceURL.path
        process.environment = environment

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            DispatchQueue.main.async {
                self?.appendOutput(text)
            }
        }

        process.terminationHandler = { [weak self] terminatedProcess in
            DispatchQueue.main.async {
                pipe.fileHandleForReading.readabilityHandler = nil
                self?.appendOutput("\n[exit \(terminatedProcess.terminationStatus)] \(action.title)\n\n")
                self?.currentProcess = nil
                self?.outputPipe = nil
            }
        }

        do {
            try process.run()
            currentProcess = process
            outputPipe = pipe
            appendOutput("$ \(action.title) :: \(action.summary)\n")
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            appendOutput("Failed to start \(action.title): \(error.localizedDescription)\n")
        }
    }

    private func currentWorkspaceURL() -> URL? {
        if let persisted = UserDefaults.standard.string(forKey: DefaultsKey.workspaceRoot),
           FileManager.default.fileExists(atPath: persisted) {
            return URL(fileURLWithPath: persisted)
        }
        if let bundledWorkspaceRoot,
           bundledWorkspaceRoot != "__WORKSPACE_ROOT__",
           FileManager.default.fileExists(atPath: bundledWorkspaceRoot) {
            return URL(fileURLWithPath: bundledWorkspaceRoot)
        }
        return nil
    }

    private func actionScriptURL() -> URL? {
        Bundle.main.resourceURL?.appendingPathComponent("litebike_operator_actions.sh")
    }

    private func updateWorkspaceDisplay() {
        if let workspaceURL = currentWorkspaceURL() {
            workspaceField?.stringValue = workspaceURL.path
        } else {
            workspaceField?.stringValue = "Workspace not set"
        }
    }

    private func appendOutput(_ text: String) {
        guard let outputView else { return }

        let attributed = NSAttributedString(
            string: text,
            attributes: [
                .font: NSFont.monospacedSystemFont(ofSize: 12, weight: .regular),
                .foregroundColor: NSColor.labelColor,
            ]
        )
        outputView.textStorage?.append(attributed)
        outputView.scrollToEndOfDocument(nil)
    }

    private func setupStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = loadTemplateStatusIcon()
            button.imagePosition = .imageOnly
            button.toolTip = "Litebike Operator Bar"
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Open Operator Console", action: #selector(showWindow(_:)), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Choose Workspace…", action: #selector(chooseWorkspace(_:)), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Copy Workspace Path", action: #selector(copyWorkspacePath(_:)), keyEquivalent: ""))
        menu.addItem(.separator())

        for action in OperatorAction.allCases {
            let item = NSMenuItem(title: action.title, action: #selector(runMappedAction(_:)), keyEquivalent: "")
            item.representedObject = action.rawValue
            item.target = self
            menu.addItem(item)
        }

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Stop Current Task", action: #selector(stopCurrentTask(_:)), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit(_:)), keyEquivalent: ""))

        for item in menu.items where item.action != nil {
            item.target = self
        }

        item.menu = menu
        statusItem = item
    }

    private func setupWindow() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1040, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Litebike Operator Bar"
        window.delegate = self
        window.isReleasedWhenClosed = false
        self.window = window

        let contentView = NSView()
        contentView.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = contentView

        let rootStack = NSStackView()
        rootStack.translatesAutoresizingMaskIntoConstraints = false
        rootStack.orientation = .vertical
        rootStack.alignment = .leading
        rootStack.spacing = 14
        contentView.addSubview(rootStack)

        NSLayoutConstraint.activate([
            rootStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 18),
            rootStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -18),
            rootStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 18),
            rootStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -18),
        ])

        let titleLabel = makeLabel(
            "Litebike Operator Bar",
            font: NSFont.systemFont(ofSize: 28, weight: .bold),
            color: .labelColor
        )
        let subtitleLabel = makeLabel(
            "Menu-bar host for build, git push, SSH, remote deploy, proxy-bridge, and termux sync actions.",
            font: NSFont.systemFont(ofSize: 13, weight: .regular),
            color: .secondaryLabelColor
        )

        rootStack.addArrangedSubview(titleLabel)
        rootStack.addArrangedSubview(subtitleLabel)

        let workspaceRow = NSStackView()
        workspaceRow.orientation = .horizontal
        workspaceRow.alignment = .centerY
        workspaceRow.spacing = 8

        let workspaceTitle = makeLabel(
            "Workspace:",
            font: NSFont.systemFont(ofSize: 12, weight: .semibold),
            color: .secondaryLabelColor
        )
        let workspaceField = NSTextField(labelWithString: "Workspace not set")
        workspaceField.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        workspaceField.lineBreakMode = .byTruncatingMiddle
        workspaceField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        workspaceField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        self.workspaceField = workspaceField

        let chooseButton = makeButton(title: "Choose Workspace…", selector: #selector(chooseWorkspace(_:)))
        let copyPathButton = makeButton(title: "Copy Path", selector: #selector(copyWorkspacePath(_:)))

        workspaceRow.addArrangedSubview(workspaceTitle)
        workspaceRow.addArrangedSubview(workspaceField)
        workspaceRow.addArrangedSubview(chooseButton)
        workspaceRow.addArrangedSubview(copyPathButton)
        rootStack.addArrangedSubview(workspaceRow)

        let buttonRows: [[OperatorAction]] = [
            [.buildRelease, .proxySSH, .openSSHTerminal],
            [.gitPushCurrent, .deployRemote, .proxyStatus],
            [.proxyStop, .syncTermux],
        ]

        for rowActions in buttonRows {
            let row = NSStackView()
            row.orientation = .horizontal
            row.alignment = .centerY
            row.spacing = 10
            for action in rowActions {
                let button = makeButton(title: action.title, selector: #selector(runMappedAction(_:)))
                button.identifier = NSUserInterfaceItemIdentifier(action.rawValue)
                button.toolTip = action.summary
                button.widthAnchor.constraint(greaterThanOrEqualToConstant: 150).isActive = true
                row.addArrangedSubview(button)
            }
            rootStack.addArrangedSubview(row)
        }

        let controlRow = NSStackView()
        controlRow.orientation = .horizontal
        controlRow.alignment = .centerY
        controlRow.spacing = 10
        controlRow.addArrangedSubview(makeButton(title: "Stop Current Task", selector: #selector(stopCurrentTask(_:))))
        controlRow.addArrangedSubview(makeButton(title: "Clear Output", selector: #selector(clearOutput(_:))))
        rootStack.addArrangedSubview(controlRow)

        let outputHeader = makeLabel(
            "Operator Output",
            font: NSFont.systemFont(ofSize: 13, weight: .semibold),
            color: .secondaryLabelColor
        )
        rootStack.addArrangedSubview(outputHeader)

        let outputView = NSTextView()
        outputView.isEditable = false
        outputView.isRichText = false
        outputView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        outputView.backgroundColor = NSColor.textBackgroundColor
        outputView.textColor = NSColor.labelColor
        self.outputView = outputView

        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder
        scrollView.documentView = outputView
        scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 420).isActive = true
        rootStack.addArrangedSubview(scrollView)

        let hintsLabel = makeLabel(
            "Remote defaults come from environment: LB_HOST, LB_USER, LB_SSH_PORT, LB_DIR, LB_REMOTE_BUILD_CMD, LB_REMOTE_AFTER_BUILD_CMD.",
            font: NSFont.systemFont(ofSize: 12, weight: .regular),
            color: .secondaryLabelColor
        )
        hintsLabel.maximumNumberOfLines = 2
        rootStack.addArrangedSubview(hintsLabel)
    }

    private func makeButton(title: String, selector: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: selector)
        button.bezelStyle = .rounded
        return button
    }

    private func makeLabel(_ string: String, font: NSFont, color: NSColor) -> NSTextField {
        let label = NSTextField(labelWithString: string)
        label.font = font
        label.textColor = color
        label.lineBreakMode = .byWordWrapping
        return label
    }

    private func loadTemplateStatusIcon() -> NSImage? {
        guard let iconURL = Bundle.main.resourceURL?.appendingPathComponent("StatusIconTemplate.png") else {
            return nil
        }
        let image = NSImage(contentsOf: iconURL)
        image?.isTemplate = true
        image?.size = NSSize(width: 18, height: 18)
        return image
    }
}

let app = NSApplication.shared
private let delegate = AppDelegate()
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
