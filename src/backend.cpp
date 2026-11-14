#include "backend.h"
#include "registry.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>

Backend::Backend(bool demo, QObject *parent) : QObject(parent), m_demo(demo) {
    m_labelPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/labels.json";
    m_timeout.setSingleShot(true);
    connect(&m_timeout, &QTimer::timeout, this, [this] {
        if (m_process) m_process->kill();
        finish(false, tr("The operation timed out. Refresh before trying again."));
    });
    refresh();
}
Backend::~Backend() { if (m_process) { m_process->disconnect(this); m_process->kill(); m_process->waitForFinished(1000); } }
QJsonObject Backend::labels() const {
    if (!QFileInfo::exists(m_labelPath)) return {};
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(readFile(m_labelPath), &error);
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
    m_keys.clear(); m_problem.clear();
    if (m_demo) {
        int n = 1;
        for (const auto &name : {tr("Everyday key"), tr("Travel key"), tr("Backup at home")}) {
            m_keys.append(QVariantMap{{"id",QString(64, QChar('a' + n))},{"name",name},{"shortId",QString("8f%1a · 42c%1").arg(n++)}});
        }
        emit changed(); return;
    }
    try {
        m_problem = checkConfiguration();
        const Registry registry(readFile("/etc/fido2/fido2"), currentUser());
        m_revision = registry.revision();
        const auto names = labels();
        int n = 1;
        for (const auto &key : registry.keys()) {
            auto name = names.value(key.id).toString();
            if (name.isEmpty()) name = tr("Key %1").arg(n);
            m_keys.append(QVariantMap{{"id",key.id},{"name",name},{"shortId",key.id.left(12)}});
            ++n;
        }
    } catch (const std::exception &e) { if (m_problem.isEmpty()) m_problem = QString::fromUtf8(e.what()); }
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
void Backend::save(const QJsonObject &request, std::function<void()> after) {
    if (m_demo) { finish(false, tr("Preview mode does not change registrations.")); return; }
    if (!QFileInfo::exists("/usr/bin/keykeep")) throw Failure(tr("Install Keykeep before changing registrations."));
    m_phase = "authorize";
    m_message = tr("Approve the system authentication prompt to save the change."); emit changed();
    start("/usr/bin/pkexec", {"/usr/bin/keykeep", "--helper"}, 120000, [this,after](QByteArray out) {
        const auto response = QJsonDocument::fromJson(out).object();
        if (!response.value("ok").toBool()) throw Failure(tr("No confirmation received. Refresh to check the registration."));
        const auto backup = response.value("backup").toString();
        try { after(); } catch (const std::exception &e) {
            finish(true, tr("Registration saved, but its name could not be saved: %1").arg(QString::fromUtf8(e.what()))); return;
        }
        finish(true, tr("Saved. Backup: %1").arg(backup));
    }, QJsonDocument(request).toJson(QJsonDocument::Compact));
}
void Backend::add(const QString &name) {
    if (m_busy) return;
    try {
        if (!m_problem.isEmpty()) throw Failure(m_problem);
        const auto label = validateName(name);
        if (m_keys.size() >= 24) throw Failure(tr("The default limit of 24 registrations has been reached."));
        if (m_demo) throw Failure(tr("Preview mode does not change registrations."));
        m_busy = true; m_phase = "detect"; m_message = tr("Checking for a connected security key…"); emit changed();
        const auto revision = m_revision;
        start("/usr/bin/fido2-token", {"-L"}, 10000, [this,label,revision](QByteArray output) {
            const auto devices = QString::fromUtf8(output).trimmed().split('\n', Qt::SkipEmptyParts);
            if (devices.size() != 1) throw Failure(tr("Connect only the key you want to add, then try again."));
            m_phase = "touch"; m_message = tr("Touch your security key when it flashes."); emit changed();
            start("/usr/bin/pamu2fcfg", {"-n"}, 40000, [this,label,revision](QByteArray output) {
                auto credential = output.trimmed();
                if (!credential.startsWith(':')) throw Failure(tr("Enrollment returned an invalid registration."));
                credential.remove(0,1); Registry::validateCredential(credential);
                const auto id = Registry::fingerprint(credential);
                save({{"action","add"},{"revision",revision},{"credential",QString::fromLatin1(credential)}},
                     [this,id,label] { saveLabel(id,label); });
            });
        });
    } catch (const std::exception &e) { finish(false, QString::fromUtf8(e.what())); }
}
void Backend::remove(const QString &id) {
    if (m_busy) return;
    try {
        if (!m_problem.isEmpty()) throw Failure(m_problem);
        if (!exists(id)) throw Failure(tr("Select a registered key first."));
        m_busy = true;
        save({{"action","remove"},{"revision",m_revision},{"id",id}}, [] {});
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
    // A privileged save may already have committed; never present cancellation as a rollback.
    if (!m_busy || m_phase == "authorize") return;
    if (m_process) { auto *p = m_process; m_process = nullptr; p->kill(); }
    finish(false, tr("Enrollment cancelled. No registration was added."));
}
