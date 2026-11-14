#include "registry.h"
#include "store.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryFile>
#include <QFile>
#include <QTextStream>
#include <QScopeGuard>
#include <pwd.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

int runHelper() {
    try {
        if (geteuid() != 0) throw Failure(appText("Administrator authentication is required."));
        bool ok = false;
        const uint uid = qEnvironmentVariable("PKEXEC_UID").toUInt(&ok);
        if (!ok || uid == 0) throw Failure(appText("Use Keykeep as a regular user through pkexec."));
        const auto *pw = getpwuid(uid);
        if (!pw) throw Failure(appText("Cannot identify the requesting user."));
        const QString user = QString::fromLocal8Bit(pw->pw_name);
        const auto config = checkConfiguration();
        if (!config.isEmpty()) throw Failure(config);
        QFile input;
        if (!input.open(stdin, QIODevice::ReadOnly)) throw Failure(appText("Cannot read request."));
        const auto payload = input.read(16385);
        if (payload.size() > 16384) throw Failure(appText("Request too large."));
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(payload, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject()) throw Failure(appText("Invalid request."));
        const auto result = applyRegistration("/etc/fido2", 0, user, doc.object());
        QTextStream(stdout) << QJsonDocument(result).toJson(QJsonDocument::Compact) << '\n';
        return 0;
    } catch (const std::exception &e) {
        QTextStream(stderr) << e.what() << '\n';
        return 1;
    }
}
