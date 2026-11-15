#pragma once
#include <QByteArray>
#include <QCoreApplication>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <stdexcept>

inline QString appText(const char *text) { return QCoreApplication::translate("Keymarchy", text); }
// Fills both placeholders in one pass, so an argument containing "%2" is not expanded again.
inline QString appText(const char *text, const QStringList &args) {
    const auto translated = appText(text);
    return args.size() == 1 ? translated.arg(args[0]) : args.size() == 2 ? translated.arg(args[0], args[1]) : translated;
}

// `source` and `args` carry the untranslated text. The privileged helper has no
// translator and reports them as they are; the interface translates them.
struct Failure : std::runtime_error {
    explicit Failure(const QString &s) : std::runtime_error(s.toStdString()), source(s) {}
    explicit Failure(const char *text, const QStringList &args = {})
        : std::runtime_error(appText(text, args).toStdString()), source(QString::fromUtf8(text)), args(args) {}
    QString source;
    QStringList args;
};
// `touch` is false when sudo accepts the registration without a touch.
// A resident registration has no key handle to look for on a connected key.
struct Key { QString id; QByteArray credential; bool touch = true; bool resident = false; };
class Registry {
public:
    Registry(QByteArray data, QString user);
    QVector<Key> keys() const;
    QByteArray add(const QByteArray &credential) const;
    QByteArray remove(const QString &id) const;
    void checkCapacity() const;
    QString revision() const;
    static QString fingerprint(const QByteArray &credential);
    // Accepts what pam_u2f accepts, so existing registrations can be listed and removed.
    static void validateCredential(const QByteArray &credential);
    // Accepts only what enrollment produces: a touch-required, non-resident registration.
    static void validateNewCredential(const QByteArray &credential);
private:
    QByteArray replace(const QVector<Key> &keys) const;
    QByteArray m_data;
    QString m_user;
    QList<QByteArray> m_lines;
    int m_index = -1;
};
QByteArray readFile(const QString &path, qint64 limit = 1024 * 1024);
QString currentUser();
QString checkPamConfiguration(const QString &pam, const QString &defaults = {});
QString checkPolkitConfiguration(const QString &pam);
QString checkConfiguration();
// Other PAM services that read the registration file. Their rules are not checked.
QStringList otherFidoServices(const QString &directory = "/etc/pam.d");
