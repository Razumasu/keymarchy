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
    static QJsonObject request(const QByteArray &data, const QString &action, const QByteArray &credential = three) {
        return {{"revision",Registry::fingerprint(data)},{"action",action},{"credential",QString::fromLatin1(credential)}};
    }
private slots:
    void initTestCase() { QQuickStyle::setStyle("Material"); }
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
    void supportsLegacyRecords() { Registry r("alice:0123abcd,4567efab\n","alice"); QCOMPARE(r.keys().size(),1); }
    void enforcesLimit() {
        Registry r("alice:\n","alice"); QByteArray data;
        for (int i=0;i<24;++i) { data=r.add(QByteArray::number(i)+",abcdef,es256,+presence"); r=Registry(data,"alice"); }
        QVERIFY_EXCEPTION_THROWN(r.add(three),Failure);
    }
    void savesBackupAndPermissions() {
        QTemporaryDir dir; const auto original="alice:"+one+':'+two+"\n";
        write(dir.filePath("fido2"),original);
        const auto result=applyRegistration(dir.path(),getuid(),"alice",request(original,"add"));
        QCOMPARE(readFile(result.value("backup").toString()),original);
        const auto saved=readFile(dir.filePath("fido2")); QCOMPARE(Registry(saved,"alice").keys().size(),3);
        struct stat st{}; QVERIFY(stat(QFile::encodeName(dir.filePath("fido2")).constData(),&st)==0); QCOMPARE(st.st_mode & 0777,mode_t(0644));
        QVERIFY(stat(QFile::encodeName(result.value("backup").toString()).constData(),&st)==0); QCOMPARE(st.st_mode & 0777,mode_t(0600));
        auto rm=request(saved,"remove"); rm.insert("id",Registry::fingerprint(three));
        applyRegistration(dir.path(),getuid(),"alice",rm);
        QCOMPARE(readFile(dir.filePath("fido2")),original);
    }
    void refusesStaleRevisions() {
        QTemporaryDir dir; auto original="alice:"+one+"\n"; write(dir.filePath("fido2"),original);
        auto req=request(original,"add"); req.insert("revision","stale");
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",req),Failure);
        QCOMPARE(readFile(dir.filePath("fido2")),original);
    }
    void rejectsSymlinkAndWritableFiles() {
        QTemporaryDir dir; auto original="alice:"+one+"\n"; write(dir.filePath("real"),original);
        QVERIFY(QFile::link(dir.filePath("real"),dir.filePath("fido2")));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(original,"add")),Failure);
        QFile::remove(dir.filePath("fido2")); write(dir.filePath("fido2"),original);
        QVERIFY(QFile::setPermissions(dir.filePath("fido2"), QFile::ReadOwner|QFile::WriteOwner|QFile::WriteOther));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(original,"add")),Failure);
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
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.filePath("safe"),getuid(),"alice",request(data,"add")),Failure);
        QFile::remove(dir.filePath("copy"));
        QVERIFY(QFile::link(dir.filePath("safe"),dir.filePath("alias")));
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.filePath("alias"),getuid(),"alice",request(data,"add")),Failure);
    }
    void refusesConcurrentWriters() {
        QTemporaryDir dir; const auto data="alice:"+one+"\n"; write(dir.filePath("fido2"),data);
        const int fd=open(QFile::encodeName(dir.filePath(".keykeep.lock")).constData(),O_RDWR|O_CREAT,0600);
        QVERIFY(fd>=0); QVERIFY(flock(fd,LOCK_EX|LOCK_NB)==0);
        QVERIFY_EXCEPTION_THROWN(applyRegistration(dir.path(),getuid(),"alice",request(data,"add")),Failure);
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
    void detectionErrorsAreNotReportedAsDisconnected() {
        const QVector<Key> keys{{"first",one}};
        const QVector<AttachedKey> devices{{"/device","YubiKey","generation-1"}};
        const auto result=detectPresence(keys,devices,[](const AttachedKey &,const Key &) { return Match::Unknown; });
        QCOMPARE(result.value("keys").toArray()[0].toObject().value("connection").toString(),QString("unknown"));
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
