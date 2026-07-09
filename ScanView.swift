import SwiftUI
import UniformTypeIdentifiers

struct ScanView: View {
    enum Phase: Equatable {
        case idle, importing, analyzing(String), done, error(String)
    }

    @State private var phase: Phase = .idle
    @State private var report: ScanReport?
    @State private var showImporter = false

    private let ipaType = UTType(filenameExtension: "ipa") ?? .data

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bg.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 18) {
                        header
                        dropCard
                        if case .analyzing(let step) = phase { progressCard(step) }
                        if case .importing = phase { progressCard("Reading file…") }
                        if case .error(let msg) = phase { errorCard(msg) }
                    }
                    .padding(18)
                }
            }
            .navigationDestination(item: $report) { ReportView(report: $0) }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [ipaType, .zip, .data],
                          allowsMultipleSelection: false) { handleImport($0) }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(Theme.accent2)
                Text("MobileGuard").font(.system(size: 20, weight: .bold))
                    .foregroundStyle(Theme.text)
                Spacer()
            }
            Text("OWASP Mobile Top 10 scanner for iOS apps")
                .font(.system(size: 13)).foregroundStyle(Theme.text2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var dropCard: some View {
        Button { showImporter = true } label: {
            VStack(spacing: 10) {
                Image(systemName: "arrow.up.doc.fill").font(.system(size: 26))
                    .foregroundStyle(Theme.accent2)
                Text("Choose an .ipa to scan").font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Theme.text)
                Text("Import from Files, iCloud or AirDrop")
                    .font(.system(size: 12)).foregroundStyle(Theme.text3)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 30)
            .background(RoundedRectangle(cornerRadius: 16).fill(Theme.surface))
            .overlay(RoundedRectangle(cornerRadius: 16)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6]))
                .foregroundStyle(Theme.border))
        }
        .disabled(isBusy)
        .opacity(isBusy ? 0.5 : 1)
    }

    private func progressCard(_ step: String) -> some View {
        HStack(spacing: 12) {
            ProgressView().tint(Theme.accent2)
            Text(step).font(.system(size: 14)).foregroundStyle(Theme.text2)
            Spacer()
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 14).fill(Theme.surface))
    }

    private func errorCard(_ msg: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Scan failed", systemImage: "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Theme.severityColor("high"))
            Text(msg).font(.system(size: 13)).foregroundStyle(Theme.text2)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(16)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(hex: 0x2A140F)))
    }

    private var isBusy: Bool {
        if case .idle = phase { return false }
        if case .error = phase { return false }
        if case .done = phase { return false }
        return true
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let e):
            phase = .error(e.localizedDescription)
        case .success(let urls):
            guard let picked = urls.first else { return }
            runScan(picked)
        }
    }

    private func runScan(_ picked: URL) {
        phase = .importing
        Task {
            do {
                // Copy the security-scoped file to a stable temp location.
                let localCopy = try copyIntoTemp(picked)
                await MainActor.run { phase = .analyzing("Unpacking and inspecting the binary…") }
                let evidence = try IPAAnalyzer.analyze(ipaURL: localCopy)
                try? FileManager.default.removeItem(at: localCopy)

                await MainActor.run { phase = .analyzing("Mapping findings to the OWASP Mobile Top 10…") }
                let result = try await SupabaseService.analyze(evidence)

                await MainActor.run {
                    report = result
                    phase = .done
                }
            } catch {
                await MainActor.run { phase = .error(error.localizedDescription) }
            }
        }
    }

    private func copyIntoTemp(_ url: URL) throws -> URL {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("upload-\(UUID().uuidString).ipa")
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: url, to: dest)
        return dest
    }
}
