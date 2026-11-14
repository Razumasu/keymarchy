#include "registry.h"
#include <QCryptographicHash>
#include <QFile>
#include <QRegularExpression>
#include <QSet>
#include <pwd.h>
#include <unistd.h>

QByteArray readFile(const QString &path, qint64 limit) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) throw Failure(appText("Cannot read %1: %2").arg(path, f.errorString()));
    const auto data = f.read(limit + 1);
    if (data.size() > limit) throw Failure(appText("File is too large: %1").arg(path));
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
    if (!encoded.match(QString::fromLatin1(fields[0])).hasMatch() || !encoded.match(QString::fromLatin1(fields[1])).hasMatch())
        throw Failure(appText("Invalid FIDO key encoding."));
    if (fields.size() == 4) {
        if (!QSet<QByteArray>{"es256", "eddsa", "rs256"}.contains(fields[2])) throw Failure(appText("Unsupported key algorithm."));
        if (!QRegularExpression("^(\\+(presence|pin|verification|resident))*$").match(QString::fromLatin1(fields[3])).hasMatch())
            throw Failure(appText("Unsupported FIDO key options."));
    }
}
Registry::Registry(QByteArray data, QString user) : m_data(data), m_user(user), m_lines(data.split('\n')) {
    if (!QRegularExpression("^[a-zA-Z0-9_.-]+[$]?$").match(user).hasMatch()) throw Failure(appText("Invalid user name."));
    for (int i = 0; i < m_lines.size(); ++i) {
        if (m_lines[i].startsWith(user.toUtf8() + ':')) {
            if (m_index != -1) throw Failure(appText("Multiple entries for this user. Repair the mapping before editing."));
            m_index = i;
        }
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
        result.append({id, fields[i]});
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
QByteArray Registry::add(const QByteArray &credential) const {
    validateCredential(credential);
    auto list = keys();
    if (list.size() >= 24) throw Failure(appText("The default limit of 24 registrations has been reached."));
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
QString checkConfiguration() {
    try {
        const auto pam = QString::fromUtf8(readFile("/etc/pam.d/sudo"));
        int matches = 0;
        for (auto line : pam.split('\n')) {
            line = line.section('#', 0, 0).simplified();
            if (!line.contains("pam_u2f.so")) continue;
            const auto words = line.split(' ');
            if (words.size() != 5 || words[0] != "auth" || words[1] != "sufficient" || words[2] != "pam_u2f.so" ||
                !words.contains("cue") || !words.contains("authfile=/etc/fido2/fido2"))
                return appText("Custom sudo FIDO settings detected. Keymarchy currently supports Omarchy's standard configuration.");
            ++matches;
        }
        if (matches != 1) return appText("Set up FIDO2 in Omarchy's Setup > Security menu first, then refresh Keymarchy.");
        if (!QRegularExpression("(?m)^auth\\s+include\\s+system-auth\\s*$").match(pam).hasMatch())
            return appText("The standard password fallback is missing. Restore it before managing keys.");
        QFile defaults("/etc/security/pam_u2f.conf");
        if (defaults.exists()) {
            const auto config = QString::fromUtf8(readFile(defaults.fileName()));
            for (const auto &line : config.split('\n')) if (!line.section('#',0,0).trimmed().isEmpty())
                return appText("Custom pam_u2f defaults detected. Keymarchy currently supports Omarchy's standard configuration.");
        }
        return {};
    } catch (const Failure &e) { return QString::fromUtf8(e.what()); }
}
