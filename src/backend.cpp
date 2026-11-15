#include "backend.h"
#include "registry.h"
#include "presence.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>
#include <memory>

static const QString helperPath = QStringLiteral("/usr/lib/keymarchy/keymarchy-helper");

Backend::Backend(bool demo, QObject *parent) : QObject(parent), m_demo(demo) {
    m_labelPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/labels.json";
    m_timeout.setSingleShot(true);
    connect(&m_timeout, &QTimer::timeout, this, [this] {
        // The helper runs as root and cannot be killed; closing its input stops a pending enrollment.
        if (m_process) { m_process->closeWriteChannel(); m_process->kill(); }
        finish(false, tr("The operation timed out. Refresh before trying again."));
    });
    m_scanTimeout.setSingleShot(true);
    m_scanTimeout.setInterval(30000);
    m_poll.setInterval(3000);
    connect(&m_poll, &QTimer::timeout, this, &Backend::scanNow);
    connect(&m_scanTimeout, &QTimer::timeout, &m_scan, &QProcess::kill);
    connect(&m_scan, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (m_acceptScan && error == QProcess::FailedToStart) detectionFailed(tr("Could not start connected-key detection."));
    });
    connect(&m_scan, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
        m_scanTimeout.stop();
        if (!m_acceptScan || m_busy) return;
        const auto out = m_scan.readAllStandardOutput();
        m_scan.readAllStandardError();
        if (code != 0 || status != QProcess::NormalExit) {
            detectionFailed(tr("Could not identify connected keys. Check the connection and refresh.")); return;
        }
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(out, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject()) {
            detectionFailed(tr("Could not read connected-key detection results.")); return;
        }
        const auto result = doc.object();
        if (result.value("revision").toString() != m_revision) { refresh(); return; }
        if (result.value("unchanged").toBool()) return;
        m_scanToken = result.value("token").toString();
        m_keys = applyPresence(m_keys, result);
        bool connected = false, unknown = false;
        for (const auto &row : m_keys) {
            connected |= row.toMap().value("connection") == "connected";
            unknown |= row.toMap().value("connection") == "unknown";
        }
        m_connectionMessage = connected ? tr("Connected keys are highlighted. Rename one to give it a memorable name.")
            : unknown ? tr("A connected key could not be identified without verification. Try Refresh.")
            : result.value("deviceCount").toInt() == 0 ? tr("No security key connected.")
            : tr("The connected key does not match a saved registration.");
        emit changed();
    });
    refresh();
}
Backend::~Backend() {
    pauseDetection();
    // The helper cannot be killed once it runs as root; closing its input makes it stop waiting for a touch.
    if (m_process) { m_process->disconnect(this); m_process->closeWriteChannel(); m_process->kill(); m_process->waitForFinished(1000); }
}
QJsonObject Backend::labels() const {
    const auto path = labelReadPath(m_labelPath, QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/keykeep/labels.json");
    if (path.isEmpty()) return {};
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(readFile(path), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) throw Failure(tr("Cannot read saved key names. Repair labels.json before renaming keys."));
    return doc.object();
}
QString Backend::validateName(const QString &name) {
    const auto n = name.trimmed();
    if (n.isEmpty() || n.size() > 80) throw Failure(tr("Use a name between 1 and 80 characters."));
    for (const auto c : n) if (!c.isPrint()) throw Failure(tr("Key names cannot contain control characters."));
    return n;
}
void Backend::saveLabel(const QString &id, const QString &name) {
    auto data = labels();
    if (name.isEmpty()) data.remove(id); else data.insert(id, validateName(name));
    if (!QDir().mkpath(QFileInfo(m_labelPath).absolutePath())) throw Failure(tr("Cannot create the key names folder."));
    QSaveFile file(m_labelPath);
    const auto bytes = QJsonDocument(data).toJson();
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) throw Failure(tr("Cannot save key names."));
}
void Backend::refresh() {
    if (m_busy) return;
    pauseDetection();
    m_scanToken.clear();
    m_keys.clear(); m_problem.clear(); m_notice.clear();
    if (m_demo) {
        int n = 1;
        for (const auto &name : {tr("Everyday key"), tr("Travel key"), tr("Backup at home")}) {
            m_keys.append(QVariantMap{{"id",QString(64, QChar('a' + n))},{"name",name},{"connection",n == 1 ? "connected" : "disconnected"},{"shortId",QString("8f%1a · 42c%1").arg(n++)}});
        }
        m_connectionMessage = tr("Connected keys are highlighted. Rename one to give it a memorable name.");
        emit changed(); return;
    }
    // Names are only descriptive: without them the keys can still be listed and removed.
    QJsonObject names;
    QStringList notices;
    try { names = labels(); } catch (const std::exception &e) { notices.append(QString::fromUtf8(e.what())); }
    const auto others = otherFidoServices();
    if (!others.isEmpty()) notices.append(tr("These services also use your registrations, and Keymarchy does not check their settings: %1").arg(others.join(", ")));
    m_notice = notices.join('\n');
    try {
        m_problem = checkConfiguration();
        const Registry registry(readFile("/etc/fido2/fido2"), currentUser());
        m_revision = registry.revision();
        int n = 1;
        for (const auto &key : registry.keys()) {
            auto name = names.value(key.id).toString();
            if (name.isEmpty()) name = tr("Key %1").arg(n);
            m_keys.append(QVariantMap{{"id",key.id},{"name",name},{"shortId",key.id.left(12)},{"connection","checking"},{"touch",key.touch}});
            ++n;
        }
    } catch (const std::exception &e) { if (m_problem.isEmpty()) m_problem = QString::fromUtf8(e.what()); }
    if (m_monitoring) { m_poll.start(); scanNow(); }
    emit changed();
}
bool Backend::exists(const QString &id) const {
    for (const auto &item : m_keys) if (item.toMap().value("id").toString() == id) return true;
    return false;
}
void Backend::finish(bool success, const QString &message) {
    m_timeout.stop();
    m_busy = false; m_phase.clear(); m_message = message;
    refresh(); emit completed(success);
}
void Backend::start(const QString &program, const QStringList &args, int timeout,
                    std::function<void(QByteArray)> done, const QByteArray &input) {
    auto *p = new QProcess(this);
    m_process = p;
    connect(p, &QProcess::errorOccurred, this, [this,p](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart && m_process == p) {
            m_process = nullptr; p->deleteLater(); finish(false, tr("Could not start %1.").arg(p->program()));
        }
    });
    connect(p, &QProcess::finished, this, [this,p,done](int code, QProcess::ExitStatus status) {
        const bool active = m_process == p;
        if (active) { m_process = nullptr; m_timeout.stop(); }
        const auto out = p->readAllStandardOutput();
        const auto err = QString::fromUtf8(p->readAllStandardError()).trimmed();
        p->deleteLater();
        if (!active || !m_busy) return;
        if (code != 0 || status != QProcess::NormalExit) {
            finish(false, err.isEmpty() ? tr("Operation cancelled or authentication denied.") : err); return;
        }
        try { done(out); } catch (const std::exception &e) { finish(false, QString::fromUtf8(e.what())); }
    });
    p->start(program, args);
    if (!input.isEmpty()) p->write(input);
    p->closeWriteChannel();
    m_timeout.start(timeout);
}
void Backend::privileged(const QString &action, const QJsonObject &request, std::function<void(const QJsonObject &)> after) {
    if (m_demo) { finish(false, tr("Preview mode does not change registrations.")); return; }
    if (!QFileInfo::exists(helperPath)) throw Failure(tr("Install Keymarchy before changing registrations."));
    m_phase = "authorize";
    m_message = action == "add" ? tr("Approve the system authentication prompt. You will then touch the key to enroll it.")
                                : tr("Approve the system authentication prompt to save the change.");
    emit changed();
    auto *p = new QProcess(this);
    m_process = p;
    // The helper writes one JSON object per line: progress first, then the result.
    auto pending = std::make_shared<QByteArray>();
    auto result = std::make_shared<QJsonObject>();
    const auto consume = [this,p,pending,result] {
        pending->append(p->readAllStandardOutput());
        for (auto end = pending->indexOf('\n'); end >= 0; end = pending->indexOf('\n')) {
            const auto line = QJsonDocument::fromJson(pending->left(end)).object();
            pending->remove(0, end + 1);
            if (line.contains("ok")) *result = line;
            else if (line.value("phase").toString() == "touch" && m_process == p && m_busy && m_phase == "authorize") {
                // Authentication is done; the helper gives up on the touch by itself after 30 seconds.
                m_phase = "touch"; m_message = tr("Touch your security key when it flashes.");
                m_timeout.start(45000); emit changed();
            }
        }
    };
    connect(p, &QProcess::readyReadStandardOutput, this, consume);
    connect(p, &QProcess::errorOccurred, this, [this,p](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart && m_process == p) {
            m_process = nullptr; p->deleteLater(); finish(false, tr("Could not start %1.").arg(p->program()));
        }
    });
    connect(p, &QProcess::finished, this, [this,p,consume,result,after](int code, QProcess::ExitStatus status) {
        const bool active = m_process == p;
        if (active) { m_process = nullptr; m_timeout.stop(); }
        consume();
        p->deleteLater();
        if (!active || !m_busy) return;
        if (code == 0 && status == QProcess::NormalExit && result->value("ok").toBool()) {
            try { after(*result); } catch (const std::exception &e) {
                finish(true, tr("Registration saved, but its name could not be saved: %1").arg(QString::fromUtf8(e.what()))); return;
            }
            finish(true, tr("Saved. Backup: %1").arg(result->value("backup").toString()));
        } else if (!result->value("error").toString().isEmpty()) {
            // The helper reports untranslated text; show it in the user's language.
            QStringList args;
            for (const auto &arg : result->value("args").toArray()) args.append(arg.toString());
            finish(false, appText(result->value("error").toString().toUtf8().constData(), args));
        } else if (code == 126 || code == 127 || status != QProcess::NormalExit) {
            finish(false, tr("Operation cancelled or authentication denied."));
        } else finish(false, tr("No confirmation received. Refresh to check the registration."));
    });
    p->start("/usr/bin/pkexec", {helperPath, action});
    // The write channel stays open: closing it tells the helper to stop waiting for a touch.
    p->write(QJsonDocument(request).toJson(QJsonDocument::Compact) + '\n');
    m_timeout.start(120000);
}
void Backend::add(const QString &name) {
    if (m_busy) return;
    try {
        if (!m_problem.isEmpty()) throw Failure(m_problem);
        const auto label = validateName(name);
        if (m_keys.size() >= 24) throw Failure(tr("The default limit of 24 registrations has been reached."));
        if (m_demo) throw Failure(tr("Preview mode does not change registrations."));
        pauseDetection();
        m_busy = true; m_phase = "detect"; m_message = tr("Checking for a connected security key…"); emit changed();
        const auto revision = m_revision;
        // Checked here only to avoid a pointless authentication prompt; the helper checks again.
        start("/usr/bin/fido2-token", {"-L"}, 10000, [this,label,revision](QByteArray output) {
            const auto devices = QString::fromUtf8(output).trimmed().split('\n', Qt::SkipEmptyParts);
            if (devices.size() != 1) throw Failure(tr("Connect only the key you want to add, then try again."));
            // The helper enrolls the key itself, so no registration is passed to it.
            privileged("add", {{"revision",revision}}, [this,label](const QJsonObject &response) {
                const auto id = response.value("id").toString();
                if (id.size() != 64) throw Failure(tr("Cannot save key names."));
                saveLabel(id, label);
            });
        });
    } catch (const std::exception &e) { finish(false, QString::fromUtf8(e.what())); }
}
void Backend::remove(const QString &id) {
    if (m_busy) return;
    try {
        if (!m_problem.isEmpty()) throw Failure(m_problem);
        if (!exists(id)) throw Failure(tr("Select a registered key first."));
        pauseDetection();
        m_busy = true;
        privileged("remove", {{"revision",m_revision},{"id",id}}, [](const QJsonObject &) {});
    } catch (const std::exception &e) { finish(false, QString::fromUtf8(e.what())); }
}
void Backend::rename(const QString &id, const QString &name) {
    if (m_busy) return;
    try {
        if (m_demo) throw Failure(tr("Preview mode does not change registrations."));
        if (!exists(id)) throw Failure(tr("Select a registered key first."));
        saveLabel(id, validateName(name)); finish(true, tr("Key renamed."));
    } catch (const std::exception &e) { finish(false, QString::fromUtf8(e.what())); }
}
void Backend::cancel() {
    if (!m_busy) return;
    if (m_phase == "touch") {
        // The helper may already be saving. Ask it to stop and report what it actually did.
        if (m_process) m_process->closeWriteChannel();
        m_phase = "cancelling"; m_message = tr("Cancelling…"); emit changed();
        return;
    }
    // The authentication prompt has its own Cancel.
    if (m_phase != "detect") return;
    if (m_process) { auto *p = m_process; m_process = nullptr; p->kill(); }
    finish(false, tr("Enrollment cancelled. No registration was added."));
}

void Backend::startMonitoring() {
    if (m_demo) return;
    m_monitoring = true;
    m_poll.start();
    scanNow();
}
void Backend::pauseDetection() {
    m_acceptScan = false;
    m_poll.stop(); m_scanTimeout.stop();
    if (m_scan.state() != QProcess::NotRunning) { m_scan.kill(); m_scan.waitForFinished(1000); }
}
void Backend::scanNow() {
    if (!m_monitoring || m_demo || m_busy || m_scan.state() != QProcess::NotRunning) return;
    if (!m_problem.isEmpty()) { detectionFailed(tr("Connected-key detection is unavailable for this configuration.")); return; }
    m_acceptScan = true;
    m_scan.start(QCoreApplication::applicationFilePath(), {"--scan", m_scanToken});
    m_scan.closeWriteChannel();
    m_scanTimeout.start();
}
void Backend::detectionFailed(const QString &message) {
    m_scanTimeout.stop(); m_scanToken.clear();
    m_connectionMessage = message;
    m_keys = applyPresence(m_keys, {});
    emit changed();
}

QString Backend::labelReadPath(const QString &current, const QString &legacy) {
    // Existing names remain visible after the rename; the next edit saves them under Keymarchy.
    if (QFileInfo::exists(current)) return current;
    if (QFileInfo::exists(legacy)) return legacy;
    return {};
}
