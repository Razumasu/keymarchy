#pragma once
#include <QObject>
#include <QVariantList>
#include <QJsonObject>
#include <QProcess>
#include <QTimer>
#include <functional>

class Backend : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList keys READ keys NOTIFY changed)
    Q_PROPERTY(QString message READ message NOTIFY changed)
    Q_PROPERTY(QString problem READ problem NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString connectionMessage READ connectionMessage NOTIFY changed)
    Q_PROPERTY(QString phase READ phase NOTIFY changed)
public:
    explicit Backend(bool demo = false, QObject *parent = nullptr);
    ~Backend() override;
    QVariantList keys() const { return m_keys; }
    QString message() const { return m_message; }
    QString problem() const { return m_problem; }
    bool busy() const { return m_busy; }
    QString connectionMessage() const { return m_connectionMessage; }
    void startMonitoring();
    QString phase() const { return m_phase; }
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void add(const QString &name);
    Q_INVOKABLE void remove(const QString &id);
    Q_INVOKABLE void rename(const QString &id, const QString &name);
    Q_INVOKABLE void cancel();
    static QString labelReadPath(const QString &current, const QString &legacy);
    static QString validateName(const QString &name);
signals:
    void changed();
    void completed(bool success);
private:
    void start(const QString &program, const QStringList &args, int timeout,
               std::function<void(QByteArray)> done, const QByteArray &input = {});
    void save(const QJsonObject &request, std::function<void()> after);
    void finish(bool success, const QString &message);
    QJsonObject labels() const;
    void saveLabel(const QString &id, const QString &name);
    bool exists(const QString &id) const;
    void scanNow();
    void pauseDetection();
    void detectionFailed(const QString &message);
    bool m_demo = false, m_busy = false;
    QVariantList m_keys;
    QString m_message, m_problem, m_revision, m_phase;
    QProcess *m_process = nullptr;
    QTimer m_timeout;
    QString m_labelPath;
    QProcess m_scan;
    QTimer m_poll, m_scanTimeout;
    QString m_scanToken, m_connectionMessage;
    bool m_monitoring = false, m_acceptScan = false;
};
