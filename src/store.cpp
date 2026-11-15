#include "registry.h"
#include "store.h"
#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QTemporaryFile>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

static void trusted(const QString &path, uid_t owner, bool directory, bool optional = false) {
    struct stat st{};
    if (lstat(QFile::encodeName(path).constData(), &st) != 0) {
        if (optional && errno == ENOENT) return;
        throw Failure("Cannot inspect %1.", {path});
    }
    if ((directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) || st.st_uid != owner || (st.st_mode & 0022) || (!directory && st.st_nlink != 1))
        throw Failure("Unsafe ownership, permissions, or file type at %1.", {path});
}
// Always retain this operation's backup, then the newest remaining backups.
// Only files this helper names and owns are removed.
static void pruneBackups(const QString &directory, uid_t owner, const QString &currentBackup, int keep) {
    static const QRegularExpression name("^fido2\\.backup\\.[A-Za-z0-9]{6}$");
    const auto currentName = QFileInfo(currentBackup).fileName();
    int kept = 1;
    for (const auto &entry : QDir(directory).entryInfoList({"fido2.backup.??????"}, QDir::Files | QDir::Hidden, QDir::Time)) {
        if (entry.fileName() == currentName) continue;
        const auto path = QFile::encodeName(entry.absoluteFilePath());
        struct stat st{};
        if (!name.match(entry.fileName()).hasMatch() || lstat(path.constData(), &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != owner) continue;
        if (++kept > keep) unlink(path.constData());
    }
}
QJsonObject applyRegistration(const QString &directory, uid_t owner, const QString &user,
                              const QJsonObject &request, const Enroll &enroll) {
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
    QString added;
    const auto action = request.value("action").toString();
    if (action == "add") {
        if (!enroll) throw Failure(appText("Unsupported operation."));
        // Refuse before asking for a touch that could not be saved.
        registry.checkCapacity();
        const auto credential = enroll();
        updated = registry.add(credential);
        added = Registry::fingerprint(credential);
    } else if (action == "remove") updated = registry.remove(request.value("id").toString());
    else throw Failure(appText("Unsupported operation."));
    // The backup is deleted again unless the new registrations are installed.
    QTemporaryFile backup(directory + "/fido2.backup.XXXXXX");
    if (!backup.open() || backup.write(original) != original.size() || !backup.flush() || fsync(backup.handle()) != 0)
        throw Failure(appText("Cannot create a complete backup. Registration was not changed."));
    // Qt keeps a temporary file nameless until its name is asked for. Name the
    // backup now, so it exists before the registrations are replaced.
    const auto backupPath = backup.fileName();
    if (backupPath.isEmpty() || !QFile::exists(backupPath))
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
    backup.setAutoRemove(false);
    const int dir = open(QFile::encodeName(directory).constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir >= 0) { fsync(dir); close(dir); }
    pruneBackups(directory, owner, backupPath, 10);
    QJsonObject result{{"ok",true},{"backup",backupPath}};
    if (!added.isEmpty()) result.insert("id", added);
    return result;
}
