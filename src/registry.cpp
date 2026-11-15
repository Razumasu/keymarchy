#include "registry.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QSet>
#include <pwd.h>
#include <unistd.h>

QByteArray readFile(const QString &path, qint64 limit) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) throw Failure("Cannot read %1: %2", {path, f.errorString()});
    const auto data = f.read(limit + 1);
    if (data.size() > limit) throw Failure("File is too large: %1", {path});
    return data;
}
QString currentUser() {
    auto *pw = getpwuid(getuid());
    if (!pw || getuid() == 0) throw Failure(appText("Open Keymarchy as your regular user, not as root."));
    return QString::fromLocal8Bit(pw->pw_name);
}
QString Registry::fingerprint(const QByteArray &c) {
    return QString::fromLatin1(QCryptographicHash::hash(c, QCryptographicHash::Sha256).toHex());
}
void Registry::validateCredential(const QByteArray &c) {
    if (c.isEmpty() || c.size() > 8192 || c.contains(':') || c.contains('\n') || c.contains('\r') || c.contains('\0'))
        throw Failure(appText("Invalid FIDO registration."));
    const auto fields = c.split(',');
    if (fields.size() != 2 && fields.size() != 4) throw Failure(appText("Unsupported FIDO registration format."));
    static const QRegularExpression encoded("^[A-Za-z0-9_+/=-]+$");
    // pamu2fcfg writes "*" in place of the key handle of a resident credential.
    const bool resident = fields.size() == 4 && fields[0] == "*";
    if ((!resident && !encoded.match(QString::fromLatin1(fields[0])).hasMatch()) || !encoded.match(QString::fromLatin1(fields[1])).hasMatch())
        throw Failure(appText("Invalid FIDO key encoding."));
    if (fields.size() == 4) {
        if (!QSet<QByteArray>{"es256", "eddsa", "rs256"}.contains(fields[2])) throw Failure(appText("Unsupported key algorithm."));
        static const QRegularExpression options("^(\\+(presence|pin|verification))*$");
        if (!options.match(QString::fromLatin1(fields[3])).hasMatch()) throw Failure(appText("Unsupported FIDO key options."));
    }
}
void Registry::validateNewCredential(const QByteArray &c) {
    validateCredential(c);
    const auto fields = c.split(',');
    const auto strict = [](const QByteArray &value) {
        // Padded, as pamu2fcfg writes it and pam_u2f decodes it.
        const auto decoded = QByteArray::fromBase64Encoding(value, QByteArray::AbortOnBase64DecodingErrors);
        return value.size() % 4 == 0 && decoded && !decoded.decoded.isEmpty();
    };
    // pam_u2f skips the touch for a registration without "+presence", so never write one.
    static const QRegularExpression options("^\\+presence(\\+verification)?(\\+pin)?$");
    if (fields.size() != 4 || !strict(fields[0]) || !strict(fields[1]) || !options.match(QString::fromLatin1(fields[3])).hasMatch())
        throw Failure(appText("Only touch-required registrations created by enrollment can be added."));
}
// The user a line belongs to, as pam_u2f reads it: strtok skips leading colons,
// stops at a NUL, and a line without any colon still names a user.
static QByteArray lineOwner(QByteArray line) {
    const auto nul = line.indexOf('\0');
    if (nul >= 0) line.truncate(nul);
    qsizetype start = 0;
    while (start < line.size() && line[start] == ':') ++start;
    const auto end = line.indexOf(':', start);
    return line.mid(start, end < 0 ? -1 : end - start);
}
Registry::Registry(QByteArray data, QString user) : m_data(data), m_user(user), m_lines(data.split('\n')) {
    if (!QRegularExpression("^[a-zA-Z0-9_.-]+[$]?$").match(user).hasMatch()) throw Failure(appText("Invalid user name."));
    const auto name = user.toUtf8();
    for (int i = 0; i < m_lines.size(); ++i) {
        if (lineOwner(m_lines[i]) != name) continue;
        // pam_u2f uses the last line that names the user, so every such line must be this one row.
        if (m_index != -1) throw Failure(appText("Multiple entries for this user. Repair the mapping before editing."));
        if (!m_lines[i].startsWith(name + ':') || m_lines[i].contains('\0'))
            throw Failure(appText("Unusual entry for this user. Repair the mapping before editing."));
        m_index = i;
    }
    keys();
}
QVector<Key> Registry::keys() const {
    QVector<Key> result;
    if (m_index < 0) return result;
    auto fields = m_lines[m_index].trimmed().split(':');
    QSet<QString> seen;
    for (int i = 1; i < fields.size(); ++i) {
        if (fields.size() == 2 && fields[i].isEmpty()) continue;
        validateCredential(fields[i]);
        const QString id = fingerprint(fields[i]);
        if (seen.contains(id)) throw Failure(appText("Duplicate registration. Repair the mapping before editing."));
        seen.insert(id);
        const auto parts = fields[i].split(',');
        // The old two-field format always requires a touch.
        result.append({id, fields[i], parts.size() == 2 || parts[3].contains("+presence"), parts[0] == "*"});
    }
    return result;
}
QString Registry::revision() const { return fingerprint(m_data); }
QByteArray Registry::replace(const QVector<Key> &keys) const {
    auto lines = m_lines;
    QByteArray line = m_user.toUtf8() + ':';
    for (int i = 0; i < keys.size(); ++i) { if (i) line += ':'; line += keys[i].credential; }
    if (m_index >= 0) lines[m_index] = line;
    else {
        if (!lines.isEmpty() && lines.last().isEmpty()) lines.removeLast();
        lines.append(line);
        lines.append(QByteArray());
    }
    return lines.join('\n');
}
void Registry::checkCapacity() const {
    if (keys().size() >= 24) throw Failure(appText("The default limit of 24 registrations has been reached."));
}
QByteArray Registry::add(const QByteArray &credential) const {
    validateNewCredential(credential);
    checkCapacity();
    auto list = keys();
    const auto id = fingerprint(credential);
    for (const auto &key : list) if (key.id == id) throw Failure(appText("This registration is already present."));
    list.append({id, credential});
    return replace(list);
}
QByteArray Registry::remove(const QString &id) const {
    auto list = keys();
    for (int i = 0; i < list.size(); ++i) if (list[i].id == id) { list.remove(i); return replace(list); }
    throw Failure(appText("That registration no longer exists. Refresh and try again."));
}
QString checkPamConfiguration(const QString &pam, const QString &defaults) {
    const auto unsupported = appText("Custom sudo authentication settings detected. Keymarchy currently supports Omarchy's standard configuration.");
    QList<QStringList> auth;
    bool hasFido = false;
    for (auto line : pam.split('\n')) {
        line = line.section('#', 0, 0).simplified();
        if (line.isEmpty()) continue;
        // Only the standard, ordered auth stack is supported. In particular,
        // a pam_deny rule between the key and password would defeat fallback.
        const auto words = line.split(' ');
        if (words.size() < 3 || line.contains('\\') || line.contains(QChar('\0'))) return unsupported;
        if (words[0] == "auth") {
            auth.append(words);
            hasFido |= words[2] == "pam_u2f.so";
        } else if (!QStringList{"account", "password", "session", "-account", "-password", "-session"}.contains(words[0]) ||
                   line.contains("pam_u2f.so")) {
            // Fail closed on includes, -auth and syntax we do not interpret.
            return unsupported;
        }
    }
    if (!hasFido) return appText("Set up FIDO2 in Omarchy's Setup > Security menu first, then refresh Keymarchy.");
    if (auth.size() != 2) return unsupported;
    const auto &key = auth[0];
    if (key.size() != 5 || key[1] != "sufficient" || key[2] != "pam_u2f.so" ||
        !key.contains("cue") || !key.contains("authfile=/etc/fido2/fido2") ||
        auth[1] != QStringList{"auth", "include", "system-auth"}) return unsupported;
    for (const auto &line : defaults.split('\n')) if (!line.section('#', 0, 0).trimmed().isEmpty())
        return appText("Custom pam_u2f defaults detected. Keymarchy currently supports Omarchy's standard configuration.");
    return {};
}
static QStringList activeLines(const QString &pam) {
    QStringList lines;
    for (const auto &line : pam.split('\n')) {
        const auto active = line.section('#', 0, 0).simplified();
        if (!active.isEmpty()) lines.append(active);
    }
    return lines;
}
QString checkPolkitConfiguration(const QString &pam) {
    if (checkPamConfiguration(pam).isEmpty()) return {};
    // Also accept the standard password-only stack. Prepending the standard
    // key rule lets the same strict validator check that form. Absence of a
    // direct pam_u2f rule alone is insufficient: custom includes can load it.
    const auto withKey = QStringLiteral("auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n") + pam;
    if (checkPamConfiguration(withKey).isEmpty()) return {};
    return appText("Custom polkit authentication settings detected. Keymarchy currently supports Omarchy's standard configuration.");
}
QString checkConfiguration() {
    try {
        const auto pam = QString::fromUtf8(readFile("/etc/pam.d/sudo"));
        const QString path = "/etc/security/pam_u2f.conf";
        const auto defaults = QFile::exists(path) ? QString::fromUtf8(readFile(path)) : QString();
        const auto sudo = checkPamConfiguration(pam, defaults);
        if (!sudo.isEmpty()) return sudo;
        // polkit authorizes changes to the registrations and reads the same file.
        const QString polkit = "/etc/pam.d/polkit-1";
        return QFile::exists(polkit) ? checkPolkitConfiguration(QString::fromUtf8(readFile(polkit))) : QString();
    } catch (const Failure &e) { return QString::fromUtf8(e.what()); }
}
QStringList otherFidoServices(const QString &directory) {
    QStringList services;
    for (const auto &entry : QDir(directory).entryInfoList(QDir::Files | QDir::Hidden, QDir::Name)) {
        if (directory == "/etc/pam.d" && (entry.fileName() == "sudo" || entry.fileName() == "polkit-1")) continue;
        try {
            for (const auto &line : activeLines(QString::fromUtf8(readFile(entry.absoluteFilePath()))))
                if (line.contains("/etc/fido2/fido2")) { services.append(entry.fileName()); break; }
        } catch (const Failure &) {} // unreadable to this user, so it cannot be reported
    }
    return services;
}
