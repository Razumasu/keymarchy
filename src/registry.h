#pragma once
#include <QByteArray>
#include <QCoreApplication>
#include <QJsonObject>
#include <QString>
#include <QVector>
#include <stdexcept>

inline QString appText(const char *text) { return QCoreApplication::translate("Keymarchy", text); }

struct Failure : std::runtime_error {
    explicit Failure(const QString &s) : std::runtime_error(s.toStdString()) {}
};
struct Key { QString id; QByteArray credential; };
class Registry {
public:
    Registry(QByteArray data, QString user);
    QVector<Key> keys() const;
    QByteArray add(const QByteArray &credential) const;
    QByteArray remove(const QString &id) const;
    QString revision() const;
    static QString fingerprint(const QByteArray &credential);
    static void validateCredential(const QByteArray &credential);
private:
    QByteArray replace(const QVector<Key> &keys) const;
    QByteArray m_data;
    QString m_user;
    QList<QByteArray> m_lines;
    int m_index = -1;
};
QByteArray readFile(const QString &path, qint64 limit = 1024 * 1024);
QString currentUser();
QString checkConfiguration();
int runHelper();
