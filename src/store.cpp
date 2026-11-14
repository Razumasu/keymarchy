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

static void trusted(const QString &path, uid_t owner, bool directory, bool optional = false) {
    struct stat st{};
    if (lstat(QFile::encodeName(path).constData(), &st) != 0) {
        if (optional && errno == ENOENT) return;
        throw Failure(appText("Cannot inspect %1.").arg(path));
    }
    if ((directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) || st.st_uid != owner || (st.st_mode & 0022) || (!directory && st.st_nlink != 1))
        throw Failure(appText("Unsafe ownership, permissions, or file type at %1.").arg(path));
}
QJsonObject applyRegistration(const QString &directory, uid_t owner, const QString &user, const QJsonObject &request) {
    const auto target = directory + "/fido2";
    trusted(directory, owner, true);
    trusted(target, owner, false);
    // Keep the lock name shared with older releases during an in-place upgrade.
    trusted(directory + "/.keykeep.lock", owner, false, true);
    const int lock = open(QFile::encodeName(directory + "/.keykeep.lock").constData(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0) throw Failure(appText("Cannot open the registration lock."));
    const auto closeLock = qScopeGuard([lock] { close(lock); });
    if (flock(lock, LOCK_EX | LOCK_NB) != 0) throw Failure(appText("Another Keymarchy operation is running. Try again shortly."));
    const auto original = readFile(target);
    Registry registry(original, user);
    if (request.value("revision").toString() != registry.revision()) throw Failure(appText("Registrations changed. Refresh and try again."));
    QByteArray updated;
    const auto action = request.value("action").toString();
    if (action == "add") updated = registry.add(request.value("credential").toString().toLatin1());
    else if (action == "remove") updated = registry.remove(request.value("id").toString());
    else throw Failure(appText("Unsupported operation."));
    QTemporaryFile backup(directory + "/fido2.backup.XXXXXX");
    backup.setAutoRemove(false);
    if (!backup.open() || backup.write(original) != original.size() || !backup.flush() || fsync(backup.handle()) != 0)
        throw Failure(appText("Cannot create a complete backup. Registration was not changed."));
    QTemporaryFile stage(directory + "/.keymarchy.new.XXXXXX");
    if (!stage.open() || stage.write(updated) != updated.size() || !stage.flush() ||
        fchmod(stage.handle(), 0644) != 0 || fsync(stage.handle()) != 0)
        throw Failure(appText("Cannot stage the updated registration."));
    // Catch changes made by other tools after the initial read as well.
    trusted(target, owner, false);
    if (readFile(target) != original) throw Failure(appText("Registrations changed during the operation. Try again."));
    if (::rename(QFile::encodeName(stage.fileName()).constData(), QFile::encodeName(target).constData()) != 0)
        throw Failure(appText("Cannot install the updated registration."));
    const int dir = open(QFile::encodeName(directory).constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir >= 0) { fsync(dir); close(dir); }
    return {{"ok",true},{"backup",backup.fileName()}};
}
