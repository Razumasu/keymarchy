// The privileged helper: /usr/lib/keymarchy/keymarchy-helper add|remove, run through pkexec.
// The action is an argument so the authentication prompt can say what is being approved.
// It reads one JSON line on stdin and writes JSON lines on stdout.
#include "enroll.h"
#include "registry.h"
#include "store.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <pwd.h>
#include <unistd.h>

static void reply(const QJsonObject &message) {
    const auto line = QJsonDocument(message).toJson(QJsonDocument::Compact) + '\n';
    fwrite(line.constData(), 1, size_t(line.size()), stdout);
    fflush(stdout);
}
// One byte at a time: what follows the line belongs to cancellation, not the request.
static QByteArray readRequest() {
    QByteArray line;
    for (;;) {
        char c;
        const auto count = read(0, &c, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || c == '\n') return line;
        line.append(c);
        if (line.size() > 16384) throw Failure("Request too large.");
    }
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    // A vanished interface must not kill the helper in the middle of saving.
    signal(SIGPIPE, SIG_IGN);
    try {
        const auto action = argc == 2 ? QString::fromLatin1(argv[1]) : QString();
        if (action != "add" && action != "remove") throw Failure("Unsupported operation.");
        if (geteuid() != 0) throw Failure("Administrator authentication is required.");
        bool ok = false;
        const uint uid = qEnvironmentVariable("PKEXEC_UID").toUInt(&ok);
        if (!ok || uid == 0) throw Failure("Use Keymarchy as a regular user through pkexec.");
        const auto *pw = getpwuid(uid);
        if (!pw) throw Failure("Cannot identify the requesting user.");
        const QString user = QString::fromLocal8Bit(pw->pw_name);
        const auto config = checkConfiguration();
        if (!config.isEmpty()) throw Failure(config);
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(readRequest(), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject()) throw Failure("Invalid request.");
        auto request = doc.object();
        request.insert("action", action);
        Enroll enroll;
        if (action == "add") enroll = [&user] {
            Enrollment options;
            options.ready = [] { reply({{"phase","touch"}}); };
            return enrollCredential(user, options);
        };
        reply(applyRegistration("/etc/fido2", 0, user, request, enroll));
        return 0;
    } catch (const Failure &e) {
        reply({{"ok",false},{"error",e.source},{"args",QJsonArray::fromStringList(e.args)}});
    } catch (const std::exception &e) {
        reply({{"ok",false},{"error",QString::fromUtf8(e.what())}});
    }
    return 1;
}
