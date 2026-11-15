#include <QtTest>
#include <QTemporaryDir>
#include <QFile>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QQuickItem>
#include <QQuickStyle>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "registry.h"
#include "presence.h"
#include "store.h"
#include "enroll.h"
#include "backend.h"
#include "theme.h"
#include "translator.h"

const QByteArray one = "aGVsbG8=,cHVibGlj,es256,+presence";
const QByteArray two = "d29ybGQ=,cHVibGlj,es256,+presence";
const QByteArray three = "dGhpcmQ=,cHVibGlj,es256,+presence";
class KeymarchyTests : public QObject {
    Q_OBJECT
    static void write(const QString &path, const QByteArray &data) {
        QFile f(path); QVERIFY(f.open(QIODevice::WriteOnly)); QCOMPARE(f.write(data), data.size());
    }
    static QJsonObject request(const QByteArray &data, const QString &action) {
        return {{"revision",Registry::fingerprint(data)},{"action",action}};
    }
    static QByteArray enrollThree() { return three; }
    static QString script(const QTemporaryDir &dir, const QString &name, const QByteArray &body) {
        const auto path = dir.filePath(name);
        write(path, "#!/bin/sh\n" + body + "\n");
        QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
        return path;
    }
    static int backups(const QTemporaryDir &dir) { return QDir(dir.path()).entryList({"fido2.backup.*"}, QDir::Files | QDir::Hidden).size(); }
private slots:
    void initTestCase() { QQuickStyle::setStyle("Material"); }
    void acceptsStandardPamConfiguration() {
        const QString pam = "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n"
                            "#%PAM-1.0\nauth include system-auth\n"
                            "account include system-auth\nsession include system-auth\n"
                            "session optional pam_systemd.so class=none\n";
        QVERIFY(checkPamConfiguration(pam).isEmpty());
        QVERIFY(checkPamConfiguration(pam, "# no defaults\n\n").isEmpty());
        const QString spaced = "  auth\tsufficient pam_u2f.so authfile=/etc/fido2/fido2 cue # key\r\n"
                               "\n auth  include\tsystem-auth # password\n"
                               "-session optional pam_systemd.so\n";
        QVERIFY(checkPamConfiguration(spaced).isEmpty());
    }
    void rejectsCustomPamConfiguration_data() {
        QTest::addColumn<QString>("pam");
        const QString key = "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n";
        const QString password = "auth include system-auth\n";
        QTest::newRow("reviewed-lockout") << key + "auth requisite pam_deny.so\n" + password;
        QTest::newRow("required-before-key") << "auth required pam_deny.so\n" + key + password;
        QTest::newRow("deny-after-password") << key + password + "auth required pam_deny.so\n";
        QTest::newRow("reordered") << password + key;
        QTest::newRow("duplicate-key") << key + key + password;
        QTest::newRow("duplicate-password") << key + password + password;
        QTest::newRow("no-key") << password;
        QTest::newRow("no-password") << key;
        QTest::newRow("optional-module-prefix") << key + "-auth required pam_deny.so\n" + password;
        QTest::newRow("extended-control") << key + "auth [default=die] pam_deny.so\n" + password;
        QTest::newRow("include-directive") << key + "@include other-auth\n" + password;
        QTest::newRow("substack") << key + "auth substack system-auth\n";
        QTest::newRow("custom-origin") << "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2 origin=custom\n" + password;
        QTest::newRow("custom-authfile") << "auth sufficient pam_u2f.so cue authfile=/etc/other\n" + password;
        QTest::newRow("malformed-line") << key + "invalid\n" + password;
    }
    void rejectsCustomPamConfiguration() {
        QFETCH(QString, pam);
        QVERIFY(!checkPamConfiguration(pam).isEmpty());
    }
    void rejectsCustomPamDefaults() {
        const QString pam = "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\nauth include system-auth\n";
        QVERIFY(!checkPamConfiguration(pam, "# default overrides\norigin=custom\n").isEmpty());
    }
    void acceptsOnlyStandardPolkitStacks() {
        const QString standard = "auth      sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\nauth      include system-auth\n\n"
                                 "account   include system-auth\npassword  include system-auth\nsession   include system-auth\n";
        QVERIFY(checkPolkitConfiguration(standard).isEmpty());
        QVERIFY(checkPolkitConfiguration("#%PAM-1.0\nauth include system-auth\naccount include system-auth\n").isEmpty());
        QVERIFY(checkPolkitConfiguration("# auth sufficient pam_u2f.so nouserok\nauth include system-auth\n").isEmpty());
        QVERIFY(checkPolkitConfiguration("  auth\tinclude system-auth # password\r\n-session optional pam_systemd.so\n").isEmpty());
        QVERIFY(!checkPolkitConfiguration("auth required pam_u2f.so cue authfile=/etc/fido2/fido2\nauth include system-auth\n").isEmpty());
        QVERIFY(!checkPolkitConfiguration("auth sufficient pam_u2f.so cue nouserok authfile=/etc/fido2/fido2\nauth include system-auth\n").isEmpty());
        QVERIFY(!checkPolkitConfiguration(standard + "auth required pam_deny.so\n").isEmpty());
    }
    void rejectsUnknownPolkitStacks_data() {
        QTest::addColumn<QString>("pam");
        QTest::newRow("indirect-fido-include") << "auth include custom-fido\naccount include system-auth\n";
        QTest::newRow("indirect-fido-substack") << "auth substack custom-fido\nauth include system-auth\n";
        QTest::newRow("include-directive") << "@include custom-fido\n";
        QTest::newRow("extra-rule") << "auth required pam_deny.so\nauth include system-auth\n";
        QTest::newRow("duplicate-password") << "auth include system-auth\nauth include system-auth\n";
        QTest::newRow("comments-only") << "# auth sufficient pam_u2f.so authfile=/etc/fido2/fido2\n";
    }
    void rejectsUnknownPolkitStacks() {
        QFETCH(QString, pam);
        QVERIFY(!checkPolkitConfiguration(pam).isEmpty());
    }
    void reportsOtherServicesUsingTheRegistrations() {
        QTemporaryDir dir;
        write(dir.filePath("login"), "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\nauth include system-auth\n");
        write(dir.filePath("commented"), "# auth sufficient pam_u2f.so authfile=/etc/fido2/fido2\nauth include system-auth\n");
        write(dir.filePath("own-file"), "auth sufficient pam_u2f.so cue\n");
        QCOMPARE(otherFidoServices(dir.path()), QStringList{"login"});
    }
    void decodesLegacyHandles_data() {
        QTest::addColumn<QByteArray>("handle");
        QTest::addColumn<QByteArray>("expected");
        QTest::newRow("url-safe") << QByteArray("-___") << QByteArray::fromHex("fbffff");
        QTest::newRow("standard") << QByteArray("+///") << QByteArray::fromHex("fbffff");
        QTest::newRow("mixed") << QByteArray("-/_/") << QByteArray::fromHex("fbffff");
        QTest::newRow("unpadded-two") << QByteArray("-w") << QByteArray::fromHex("fb");
        QTest::newRow("unpadded-three") << QByteArray("-_8") << QByteArray::fromHex("fbff");
        QTest::newRow("padded-two") << QByteArray("-w==") << QByteArray::fromHex("fb");
        QTest::newRow("padded-three") << QByteArray("-_8=") << QByteArray::fromHex("fbff");
    }
    void decodesLegacyHandles() {
        QFETCH(QByteArray, handle);
        QFETCH(QByteArray, expected);
        const auto credential = handle + ",047890abcdef";
        const QByteArray mapping = "alice:" + credential + '\n';
        Registry registry(mapping, "alice");
        QCOMPARE(decodeCredentialHandle(registry.keys()[0].credential), expected);
        QCOMPARE(registry.keys()[0].credential, credential);
        QCOMPARE(registry.keys()[0].id, Registry::fingerprint(credential));
        QCOMPARE(registry.revision(), Registry::fingerprint(mapping));
    }
    void rejectsInvalidHandlesAndKeepsModernDecodingStrict() {
        QCOMPARE(decodeCredentialHandle(one), QByteArray("hello"));
        QCOMPARE(decodeCredentialHandle("+///,cHVibGlj,es256,+presence"), QByteArray::fromHex("fbffff"));
        QVERIFY_EXCEPTION_THROWN(decodeCredentialHandle("-___,cHVibGlj,es256,+presence"), Failure);
        QVERIFY_EXCEPTION_THROWN(decodeCredentialHandle("a,047890abcdef"), Failure);
        QVERIFY_EXCEPTION_THROWN(decodeCredentialHandle("a=bc,047890abcdef"), Failure);
        QVERIFY_EXCEPTION_THROWN(decodeCredentialHandle("bad"), Failure);
    }
    void preservesOtherUsersAndExistingKeys() {
        const auto data = "# mapping\nother:" + three + "\nalice:" + one + ':' + two + "\n";
        Registry r(data,"alice"); const auto updated = r.add(three);
        QVERIFY(updated.startsWith("# mapping\nother:" + three + '\n'));
        Registry next(updated,"alice"); QCOMPARE(next.keys().size(),3);
        QCOMPARE(next.remove(Registry::fingerprint(three)),data);
    }
    void removesOnlySelectedKey() {
        Registry r("alice:"+one+':'+two+':'+three+"\n", "alice");
        Registry next(r.remove(Registry::fingerprint(two)),"alice");
        QCOMPARE(next.keys().size(),2); QCOMPARE(next.keys()[0].credential,one); QCOMPARE(next.keys()[1].credential,three);
        QVERIFY_EXCEPTION_THROWN(r.remove("missing"),Failure);
    }
    void lastKeyAndFirstKey() {
        Registry r("alice:"+one+"\n", "alice");
        QCOMPARE(r.remove(Registry::fingerprint(one)),QByteArray("alice:\n"));
        Registry empty("alice:\n","alice"); QCOMPARE(empty.add(one),QByteArray("alice:"+one+"\n"));
        Registry absent("other:"+two,"alice");
        QCOMPARE(Registry(absent.add(one),"alice").keys().size(),1);
    }
    void refusesMalformedOrAmbiguousRecords() {
        QVERIFY_EXCEPTION_THROWN(Registry("alice:"+one+"\nalice:"+two,"alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("alice:"+one+':'+one,"alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("alice:bad","alice"),Failure);
        Registry r("alice:"+one,"alice");
        QVERIFY_EXCEPTION_THROWN(r.add(two+"\nroot:"+three),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add(one),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("","bad:name"),Failure);
    }
    void matchesUserRowsLikePamU2f() {
        // pam_u2f skips leading colons and uses the last line naming the user.
        QVERIFY_EXCEPTION_THROWN(Registry("alice:"+one+"\n:alice:"+two+"\n","alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry(":alice:"+two+"\n","alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("::alice:"+two+"\n","alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("alice:"+one+"\nalice\n","alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry("alice\n","alice"),Failure);
        QVERIFY_EXCEPTION_THROWN(Registry(QByteArray("alice\0x:",8)+one+"\n","alice"),Failure);
        QCOMPARE(Registry("alice:"+one+"\n:bob:"+two+"\nalicia:"+three+"\n alice:"+three+"\n","alice").keys().size(),1);
    }
    void addsOnlyTouchRequiredEnrollmentOutput() {
        Registry r("alice:"+one+"\n","alice");
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ=,cHVibGlj,es256,"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ=,cHVibGlj,es256,+pin"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ=,cHVibGlj,es256,+verification+pin"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ=,cHVibGlj,es256,+presence+presence"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("*,cHVibGlj,es256,+presence"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("0123abcd,4567efab"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ,cHVibGlj,es256,+presence"),Failure);
        QVERIFY_EXCEPTION_THROWN(r.add("d29ybGQ=,cHVibGlj,es256,+presence,extra"),Failure);
        QCOMPARE(Registry(r.add(two),"alice").keys().size(),2);
        QCOMPARE(Registry(r.add("d29ybGQ=,cHVibGlj,eddsa,+presence+verification+pin"),"alice").keys().size(),2);
    }
    void listsTouchlessAndResidentRegistrations() {
        const QByteArray touchless = "d29ybGQ=,cHVibGlj,es256,", pinOnly = "dGhpcmQ=,cHVibGlj,es256,+pin", resident = "*,cHVibGlj,es256,+presence+pin";
        Registry r("alice:"+one+':'+touchless+':'+pinOnly+':'+resident+":0123abcd,4567efab\n","alice");
        const auto keys = r.keys();
        QCOMPARE(keys.size(),5);
        QVERIFY(keys[0].touch); QVERIFY(!keys[1].touch); QVERIFY(!keys[2].touch); QVERIFY(keys[3].touch); QVERIFY(keys[4].touch);
        QVERIFY(keys[3].resident); QVERIFY(!keys[0].resident); QVERIFY(!keys[4].resident);
        // Existing registrations stay untouched while another one is removed.
        QCOMPARE(r.remove(keys[1].id), QByteArray("alice:"+one+':'+pinOnly+':'+resident+":0123abcd,4567efab\n"));
        QVERIFY_EXCEPTION_THROWN(Registry("alice:*,4567efab\n","alice"),Failure);
    }
    void supportsLegacyRecords() { Registry r("alice:0123abcd,4567efab\n","alice"); QCOMPARE(r.keys().size(),1); }
    void enforcesLimit() {
        Registry r("alice:\n","alice"); QByteArray data;
        for (int i=0;i<24;++i) { data=r.add(QByteArray::number(i).toBase64()+",cHVibGlj,es256,+presence"); r=Registry(data,"alice"); }
        QVERIFY_EXCEPTION_THROWN(r.add(three),Failure);
    }
    void savesBackupAndPermissions() {
        QTemporaryDir dir; const auto original="alice:"+one+':'+two+"\n";
        write(dir.filePath("fido2"),original);
        const auto result=applyRegistration(dir.path(),getuid(),"alice",request(original,"add"),enrollThree);
        QCOMPARE(result.value("id").toString(),Registry::fingerprint(three));
        QCOMPARE(readFile(result.value("backup").toString()),original);
        const auto saved=readFile(dir.filePath("fido2")); QCOMPARE(Registry(saved,"alice").keys().size(),3);
        struct stat st{}; QVERIFY(stat(QFile::encodeName(dir.filePath("fido2")).constData(),&st)==0); QCOMPARE(st.st_mode & 0777,mode_t(0644));
        QVERIFY(stat(QFile::encodeName(result.value("backup").toString()).constData(),&st)==0); QCOMPARE(st.st_mode & 0777,mode_t(0600));
        auto rm=request(saved,"remove"); rm.insert("id",Registry::fingerprint(three));
        QVERIFY(!applyRegistration(dir.path(),getuid(),"alice",rm).contains("id"));
        QCOMPARE(readFile(dir.filePath("fido2")),original);
    }
    void addsOnlyWhatEnrollmentReturns() {
        QTemporaryDir dir; const auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        auto req=request(original,"add"); req.insert("credential",QString::fromLatin1(two));
        // A registration in the request is ignored, and nothing is added without enrolling.
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",req),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),original);
        applyRegistration(dir.path(),getuid(),"alice",req,enrollThree);
        QCOMPARE(readFile(dir.filePath("fido2")),QByteArray("alice:"+one+':'+three+"\n"));
        const auto saved=readFile(dir.filePath("fido2"));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(saved,"add"),[] { return QByteArray("d29ybGQ=,cHVibGlj,es256,"); }),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),saved);
    }
    void doesNotAskForATouchItCannotSave() {
        QTemporaryDir dir; bool asked=false; const Enroll enroll=[&] { asked=true; return three; };
        const auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        auto stale=request(original,"add"); stale.insert("revision","stale");
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",stale,enroll),Failure);
        QByteArray full="alice:";
        for (int i=0;i<24;++i) full+=(i ? ":" : "")+QByteArray::number(i).toBase64()+",cHVibGlj,es256,+presence";
        full+='\n'; write(dir.filePath("fido2"),full);
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(full,"add"),enroll),Failure);
        QVERIFY(!asked);
    }
    void leavesNoBackupWhenTheChangeIsRefused() {
        QTemporaryDir dir; const auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        const auto changed="alice:"+one+':'+two+"\n";
        // Another tool rewrites the file while the key waits for its touch.
        const Enroll enroll=[&] { write(dir.filePath("fido2"),changed); return three; };
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(original,"add"),enroll),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),changed);
        QCOMPARE(QDir(dir.path()).entryList(QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot),QStringList({".keykeep.lock","fido2"}));
    }
    void keepsTheTenNewestBackups() {
        QTemporaryDir dir; const auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        const auto now=QDateTime::currentDateTime();
        for (int i=0;i<12;++i) {
            const auto path=dir.filePath(QString("fido2.backup.old%1").arg(i,3,10,QChar('0')));
            write(path,"old"); QFile f(path); QVERIFY(f.open(QIODevice::ReadWrite));
            QVERIFY(f.setFileTime(now.addDays(-1-i),QFileDevice::FileModificationTime));
        }
        write(dir.filePath("fido2.backup.by-hand"),"mine");
        const auto result=applyRegistration(dir.path(),getuid(),"alice",request(original,"add"),enrollThree);
        QCOMPARE(backups(dir),11);
        QVERIFY(QFile::exists(result.value("backup").toString()));
        QVERIFY(QFile::exists(dir.filePath("fido2.backup.by-hand")));
        QVERIFY(QFile::exists(dir.filePath("fido2.backup.old008")));
        QVERIFY(!QFile::exists(dir.filePath("fido2.backup.old009")));
        QVERIFY(!QFile::exists(dir.filePath("fido2.backup.old011")));
    }
    void keepsCurrentBackupAfterClockRollback_data() {
        QTest::addColumn<QString>("action");
        QTest::newRow("add") << "add";
        QTest::newRow("remove") << "remove";
    }
    void keepsCurrentBackupAfterClockRollback() {
        QFETCH(QString, action);
        QTemporaryDir dir; const auto original="alice:"+one+"\n";
        write(dir.filePath("fido2"),original);
        const auto future=QDateTime::currentDateTime().addDays(1);
        for (int i=0;i<10;++i) {
            const auto path=dir.filePath(QString("fido2.backup.old%1").arg(i,3,10,QChar('0')));
            write(path,"old"); QFile f(path); QVERIFY(f.open(QIODevice::ReadWrite));
            QVERIFY(f.setFileTime(future.addSecs(i),QFileDevice::FileModificationTime));
        }
        auto req=request(original,action); req.insert("id",Registry::fingerprint(one));
        const auto result=applyRegistration(dir.path(),getuid(),"alice",req,enrollThree);
        QVERIFY(result.value("ok").toBool());
        QVERIFY(QFile::exists(result.value("backup").toString()));
        QCOMPARE(readFile(result.value("backup").toString()),original);
        QCOMPARE(backups(dir),10);
        QVERIFY(!QFile::exists(dir.filePath("fido2.backup.old000")));
        QVERIFY(QFile::exists(dir.filePath("fido2.backup.old009")));
    }
    void enrollsTheOnlyConnectedKey() {
        QTemporaryDir dir; Enrollment options; options.cancelFd=-1; bool ready=false; options.ready=[&] { ready=true; };
        options.lister=script(dir,"list","echo '/dev/hidraw1: vendor=0x1050, product=0x0407 (Yubico YubiKey)'");
        // Succeeds only for the expected arguments, a clean environment, no terminal and an unreadable stdin.
        options.enroller=script(dir,"enroll","[ \"$*\" = '-n -u alice' ] || exit 2\n[ \"$PATH\" = /usr/bin ] || exit 3\n"
                                             "[ -z \"$HOME$USER\" ] || exit 4\nif cat >/dev/null 2>&1; then exit 5; fi\n"
                                             "if ( : </dev/tty ) 2>/dev/null; then exit 6; fi\nprintf ':" + three + "\\n'");
        QCOMPARE(enrollCredential("alice",options),three);
        QVERIFY(ready);
        options.lister=script(dir,"list-two","echo one; echo two");
        QVERIFY_EXCEPTION_THROWN(enrollCredential("alice",options),Failure);
        options.lister=script(dir,"list-none","true");
        QVERIFY_EXCEPTION_THROWN(enrollCredential("alice",options),Failure);
    }
    void reportsEnrollmentFailures() {
        QTemporaryDir dir; Enrollment options; options.cancelFd=-1;
        options.lister=script(dir,"list","echo key");
        const auto failure=[&](const QByteArray &body) {
            options.enroller=script(dir,"enroll",body);
            try { enrollCredential("alice",options); } catch (const Failure &e) { return e.source; }
            return QString("no failure");
        };
        QVERIFY(failure("echo 'Enter PIN for /dev/hidraw1: error: failed to read pin' >&2; exit 1").contains("PIN"));
        QVERIFY(failure("echo 'error: fido_dev_make_cred (54) FIDO_ERR_PIN_REQUIRED' >&2; exit 1").contains("PIN"));
        QVERIFY(failure("echo 'error: fido_dev_make_cred (39) FIDO_ERR_ACTION_TIMEOUT' >&2; exit 1").startsWith("Enrollment failed."));
        QCOMPARE(failure("echo not-a-registration"),QString("Enrollment returned an invalid registration."));
        options.timeout=200;
        QVERIFY(failure("sleep 5").startsWith("No touch was detected"));
    }
    void cancelsEnrollmentWhenTheRequesterGoesAway() {
        QTemporaryDir dir; Enrollment options; options.lister=script(dir,"list","echo key");
        options.enroller=script(dir,"enroll","sleep 5; printf ':" + three + "\\n'");
        int fds[2]; QVERIFY(pipe2(fds,O_CLOEXEC)==0); options.cancelFd=fds[0];
        // Like the interface closing its end of the pipe while the key waits for a touch.
        options.ready=[&] { close(fds[1]); };
        QElapsedTimer clock; clock.start();
        try { enrollCredential("alice",options); QFAIL("enrollment was not cancelled"); }
        catch (const Failure &e) { QVERIFY(e.source.startsWith("Enrollment cancelled")); }
        QVERIFY(clock.elapsed()<3000);
        close(fds[0]);
    }
    void keepsUntranslatedTextForTheHelper() {
        const Failure plain("Unsupported operation."), detailed("Cannot read %1: %2",{"/a%2","denied"});
        QCOMPARE(plain.source,QString("Unsupported operation.")); QVERIFY(plain.args.isEmpty());
        QCOMPARE(detailed.source,QString("Cannot read %1: %2")); QCOMPARE(detailed.args,QStringList({"/a%2","denied"}));
        QCOMPARE(QString::fromUtf8(detailed.what()),QString("Cannot read /a%2: denied"));
    }
    void refusesStaleRevisions() {
        QTemporaryDir dir; auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        auto req=request(original,"add"); req.insert("revision","stale");
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",req,enrollThree),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),original);
    }
    void rejectsSymlinkAndWritableFiles() {
        QTemporaryDir dir; auto original="alice:"+one+"\n"; write(dir.filePath("real"),original);
        QVERIFY(QFile::link(dir.filePath("real"),dir.filePath("fido2")));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(original,"add"),enrollThree),Failure);
        QFile::remove(dir.filePath("fido2")); write(dir.filePath("fido2"),original);
        QVERIFY(QFile::setPermissions(dir.filePath("fido2"), QFile::ReadOwner|QFile::WriteOwner|QFile::WriteOther));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(original,"add"),enrollThree),Failure);
    }
    void cannotChangeOtherUserViaRequest() {
        QTemporaryDir dir; auto original="alice:"+one+"\nother:"+two+"\n"; write(dir.filePath("fido2"),original);
        auto req=request(original,"remove"); req.insert("id",Registry::fingerprint(two)); req.insert("user","other");
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",req),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),original);
    }
    void rejectsHardLinksAndDirectorySymlinks() {
        QTemporaryDir dir; QDir(dir.path()).mkdir("safe");
        const auto data="alice:"+one+"\n";
        const auto target=dir.filePath("safe/fido2"); write(target,data);
        QVERIFY(::link(QFile::encodeName(target).constData(),QFile::encodeName(dir.filePath("copy")).constData())==0);
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.filePath("safe"),getuid(),"alice",request(data,"add"),enrollThree),Failure);
        QFile::remove(dir.filePath("copy"));
        QVERIFY(QFile::link(dir.filePath("safe"),dir.filePath("alias")));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.filePath("alias"),getuid(),"alice",request(data,"add"),enrollThree),Failure);
    }
    void refusesConcurrentWriters() {
        QTemporaryDir dir; const auto data="alice:"+one+"\n"; write(dir.filePath("fido2"),data);
        const int fd=open(QFile::encodeName(dir.filePath(".keykeep.lock")).constData(),O_RDWR|O_CREAT,0600);
        QVERIFY(fd>=0); QVERIFY(flock(fd,LOCK_EX|LOCK_NB)==0);
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(data,"add"),enrollThree),Failure);
        close(fd); QCOMPARE(readFile(dir.filePath("fido2")),data);
    }
    void detectsExactRegistrationAndDisconnection() {
        const QVector<Key> keys{{"first",one},{"second",two}};
        const QVector<AttachedKey> devices{{"/device","YubiKey","generation-1"}};
        const auto result=detectPresence(keys,devices,[](const AttachedKey &,const Key &key) {
            return key.id=="second" ? Match::Present : Match::Absent;
        });
        const auto rows=result.value("keys").toArray();
        QCOMPARE(rows[0].toObject().value("connection").toString(),QString("disconnected"));
        QCOMPARE(rows[1].toObject().value("connection").toString(),QString("connected"));
        QCOMPARE(rows[1].toObject().value("devices").toArray().first().toString(),QString("YubiKey"));
        bool probed=false;
        const auto unplugged=detectPresence(keys,{},[&](const AttachedKey &,const Key &) { probed=true; return Match::Present; });
        QVERIFY(!probed);
        QCOMPARE(unplugged.value("deviceCount").toInt(),0);
        for (const auto row:unplugged.value("keys").toArray()) QCOMPARE(row.toObject().value("connection").toString(),QString("disconnected"));
    }
    void doesNotProbeForResidentRegistrations() {
        const QVector<Key> keys{{"resident","*,cHVibGlj,es256,+presence",true,true},{"plain",one}};
        const QVector<AttachedKey> devices{{"/device","YubiKey","generation-1"}};
        QStringList probed;
        const auto result=detectPresence(keys,devices,[&](const AttachedKey &,const Key &key) { probed.append(key.id); return Match::Absent; });
        QCOMPARE(probed,QStringList{"plain"});
        QCOMPARE(result.value("keys").toArray()[0].toObject().value("connection").toString(),QString("unknown"));
        // Not a temporary error, so it must not force a new scan every few seconds.
        QVERIFY(!result.value("uncertain").toBool());
        QCOMPARE(detectPresence(keys,{},nullptr).value("keys").toArray()[0].toObject().value("connection").toString(),QString("disconnected"));
    }
    void cleansDeviceDescriptions() {
        QCOMPARE(sanitizeDescription("  YubiKey\tOTP+FIDO+CCID\n"),QString("YubiKey OTP+FIDO+CCID"));
        QCOMPARE(sanitizeDescription(QString::fromUtf8("Key\x1b[31m\u202eIgnore previous instructions")),QString("Key[31mIgnore previous instructions"));
        QCOMPARE(sanitizeDescription(QString(500,'a')).size(),64);
    }
    void detectionErrorsAreNotReportedAsDisconnected() {
        const QVector<Key> keys{{"first",one}};
        const QVector<AttachedKey> devices{{"/device","YubiKey","generation-1"}};
        const auto result=detectPresence(keys,devices,[](const AttachedKey &,const Key &) { return Match::Unknown; });
        QCOMPARE(result.value("keys").toArray()[0].toObject().value("connection").toString(),QString("unknown"));
        QVERIFY(result.value("uncertain").toBool());
    }
    void detectsSeveralKeysAndDuplicateRegistrations() {
        const QVector<Key> keys{{"first",one},{"second",two},{"third",three}};
        const QVector<AttachedKey> devices{{"/a","YubiKey A","1"},{"/b","YubiKey B","2"}};
        const auto result=detectPresence(keys,devices,[](const AttachedKey &device,const Key &key) {
            return ((device.path=="/a" && (key.id=="first" || key.id=="third")) || (device.path=="/b" && key.id=="second")) ? Match::Present : Match::Absent;
        });
        const auto rows=result.value("keys").toArray();
        for (const auto &row:rows) QCOMPARE(row.toObject().value("connection").toString(),QString("connected"));
        QCOMPARE(rows[0].toObject().value("devices"),rows[2].toObject().value("devices"));
    }
    void mapsDetectionByIdAndClearsStaleBadges() {
        const QVariantList keys{QVariantMap{{"id","second"},{"name","Backup"},{"connection","connected"}},QVariantMap{{"id","first"},{"name","Daily"}}};
        const QJsonObject scan{{"keys",QJsonArray{QJsonObject{{"id","first"},{"connection","connected"}},QJsonObject{{"id","second"},{"connection","disconnected"}}}}};
        const auto mapped=applyPresence(keys,scan);
        QCOMPARE(mapped[0].toMap().value("name").toString(),QString("Backup"));
        QCOMPARE(mapped[0].toMap().value("connection").toString(),QString("disconnected"));
        QCOMPARE(mapped[1].toMap().value("connection").toString(),QString("connected"));
        const auto failed=applyPresence(mapped,{});
        for (const auto &row:failed) QCOMPARE(row.toMap().value("connection").toString(),QString("unknown"));
    }
    void preservesLegacyNamesAfterRename() {
        QTemporaryDir dir;
        const auto legacy=dir.filePath("legacy-labels.json"), current=dir.filePath("labels.json");
        QCOMPARE(Backend::labelReadPath(current,legacy),QString());
        write(legacy,R"({"id":"My backup"})");
        QCOMPARE(Backend::labelReadPath(current,legacy),legacy);
        write(current,R"({"id":"My everyday key"})");
        QCOMPARE(Backend::labelReadPath(current,legacy),current);
        QCOMPARE(readFile(legacy),QByteArray(R"({"id":"My backup"})"));
    }
    void validatesNames() {
        QCOMPARE(Backend::validateName("  Backup  "),QString("Backup"));
        QVERIFY_EXCEPTION_THROWN(Backend::validateName("\n"),Failure);
        QVERIFY_EXCEPTION_THROWN(Backend::validateName("key\nname"),Failure);
    }
    void themeAndLanguage() {
        QTemporaryDir dir; QDir(dir.path()).mkdir("theme"); write(dir.filePath("theme/colors.toml"),"accent = '#112233'\n");
        Theme theme(dir.path()); QCOMPARE(theme.accent(),QString("#112233"));
        write(dir.filePath("language"),"da\n"); Translator t(dir.filePath("language"));
        QCOMPARE(t.translate("Main","Add key"),QString::fromUtf8("Tilføj nøgle"));
    }
    void realWindowDialogsAndTranslation() {
        QTemporaryDir dir; write(dir.filePath("language"),"en\n");
        Theme theme(dir.path()); Translator translator(dir.filePath("language")); qApp->installTranslator(&translator);
        Backend backend(true); QQmlApplicationEngine engine;
        engine.rootContext()->setContextProperty("backend",&backend);
        engine.rootContext()->setContextProperty("theme",&theme);
        engine.rootContext()->setContextProperty("translator",&translator);
        connect(&translator,&Translator::changed,&engine,&QQmlEngine::retranslate);
        QSignalSpy warnings(&engine,&QQmlEngine::warnings);
        engine.load(QUrl("qrc:/Main.qml")); QVERIFY(!engine.rootObjects().isEmpty());
        auto *win=qobject_cast<QQuickWindow*>(engine.rootObjects().first()); QVERIFY(win);
        QTest::qWait(150);
        int connectedBadges=0;
        std::function<void(QQuickItem *)> inspect = [&](QQuickItem *item) {
            if (item->objectName()=="connectionBadge" && item->property("text").toString()=="Connected") ++connectedBadges;
            for (auto *child:item->childItems()) inspect(child);
        };
        inspect(win->contentItem());
        QCOMPARE(connectedBadges,1);
        auto *button=win->findChild<QQuickItem*>("addButton"); QVERIFY(button);
        const auto point=button->mapToScene(QPointF(button->width()/2,button->height()/2)).toPoint();
        QTest::mouseClick(win,Qt::LeftButton,Qt::NoModifier,point);
        auto *dialog=win->findChild<QObject*>("nameDialog"); QVERIFY(dialog);
        QTRY_VERIFY(dialog->property("visible").toBool());
        auto *field=win->findChild<QObject*>("nameField"); QVERIFY(field);
        field->setProperty("text","Query key");
        QTest::keyClick(win,Qt::Key_Q); QVERIFY(win->isVisible());
        QMetaObject::invokeMethod(dialog,"reject");
        QTRY_VERIFY(!dialog->property("visible").toBool());
        // Space starts an enrollment, except on a focused button, where it presses that button.
        auto *refresh=win->findChild<QQuickItem*>("refreshButton"); QVERIFY(refresh);
        refresh->forceActiveFocus(); QTRY_VERIFY(refresh->hasActiveFocus());
        QSignalSpy refreshed(&backend,&Backend::changed);
        QTest::keyClick(win,Qt::Key_Space); QTest::qWait(150);
        QVERIFY(!dialog->property("visible").toBool()); QVERIFY(refreshed.count()>0);
        auto *keys=win->findChild<QQuickItem*>("keyList"); QVERIFY(keys);
        keys->forceActiveFocus(); QTRY_VERIFY(keys->hasActiveFocus());
        QTest::keyClick(win,Qt::Key_Space);
        QTRY_VERIFY(dialog->property("visible").toBool());
        QMetaObject::invokeMethod(dialog,"reject");
        QTRY_VERIFY(!dialog->property("visible").toBool());
        auto *list=win->findChild<QObject*>("keyList"); QVERIFY(list); list->setProperty("currentIndex",0);
        QTest::keyClick(win,Qt::Key_Delete);
        auto *remove=win->findChild<QObject*>("removeDialog"); QVERIFY(remove);
        QTRY_VERIFY(remove->property("visible").toBool()); QMetaObject::invokeMethod(remove,"reject");
        write(dir.filePath("language"),"da\n");
        QTRY_COMPARE(translator.language(),QString("da"));
        QTRY_COMPARE(button->property("text").toString(),QString::fromUtf8("Tilføj nøgle"));
        QTest::qWait(300);
        QVERIFY(win->grabWindow().save(QDir::current().filePath("danish-preview.png")));
        QCOMPARE(warnings.count(),0);
        qApp->removeTranslator(&translator);
    }
};
QTEST_MAIN(KeymarchyTests)
#include "keymarchy_tests.moc"
