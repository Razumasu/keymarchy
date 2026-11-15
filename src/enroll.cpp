#include "enroll.h"
#include "registry.h"
#include <QElapsedTimer>
#include <QProcess>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

// The interface keeps its end of the pipe open for as long as it wants the key.
static bool cancelled(int fd) {
    for (;;) {
        struct pollfd state{fd, POLLIN, 0};
        const int ready = poll(&state, 1, 0);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) return false;
        if (ready < 0 || !(state.revents & POLLIN)) return true;
        char discarded[256];
        const auto count = read(fd, discarded, sizeof discarded);
        if (count == 0) return true;
        if (count < 0 && errno == EAGAIN) return false;
        if (count < 0 && errno != EINTR) return true;
    }
}
struct Output { bool ok; QByteArray out, err; };
static Output run(const QString &program, const QStringList &args, int timeout, int cancelFd,
                  const std::function<void()> &started, const char *expired) {
    QProcess process;
    QProcessEnvironment environment;
    environment.insert("PATH", "/usr/bin");
    environment.insert("LC_ALL", "C");
    process.setProcessEnvironment(environment);
    // No terminal and an unreadable stdin. pamu2fcfg would otherwise read an
    // empty PIN from them and spend one of the key's PIN attempts on it.
    process.setChildProcessModifier([] {
        setsid();
        const int unreadable = open("/dev/null", O_WRONLY);
        if (unreadable < 0 || dup2(unreadable, 0) < 0) _exit(126);
        if (unreadable != 0) close(unreadable);
    });
    process.start(program, args, QIODevice::ReadOnly);
    if (!process.waitForStarted(5000)) throw Failure("Could not start %1.", {program});
    if (started) started();
    QElapsedTimer clock;
    clock.start();
    while (!process.waitForFinished(100) && process.state() != QProcess::NotRunning) {
        const bool stop = cancelFd >= 0 && cancelled(cancelFd);
        if (!stop && clock.elapsed() < timeout) continue;
        process.kill();
        process.waitForFinished(2000);
        throw Failure(stop ? "Enrollment cancelled. No registration was added." : expired);
    }
    return {process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
            process.readAllStandardOutput(), process.readAllStandardError()};
}
QByteArray enrollCredential(const QString &user, const Enrollment &options) {
    const auto listed = run(options.lister, {"-L"}, 10000, options.cancelFd, {}, "Could not list the connected security keys.");
    if (!listed.ok) throw Failure("Could not list the connected security keys.");
    // pamu2fcfg enrolls the first key it finds, so there must be no doubt which one that is.
    if (QString::fromUtf8(listed.out).split('\n', Qt::SkipEmptyParts).size() != 1)
        throw Failure("Connect only the key you want to add, then try again.");
    const auto enrolled = run(options.enroller, {"-n", "-u", user}, options.timeout, options.cancelFd, options.ready,
                              "No touch was detected in time. No registration was added.");
    if (!enrolled.ok) {
        if (enrolled.err.toUpper().contains("PIN"))
            throw Failure("This key asks for its PIN during enrollment, which Keymarchy cannot provide. No registration was added.");
        QString detail;
        for (const auto c : QString::fromUtf8(enrolled.err).simplified()) if (c.isPrint() && detail.size() < 200) detail += c;
        throw Failure("Enrollment failed. No registration was added. %1", {detail});
    }
    auto credential = enrolled.out.trimmed();
    if (!credential.startsWith(':')) throw Failure("Enrollment returned an invalid registration.");
    credential.remove(0, 1);
    return credential;
}
